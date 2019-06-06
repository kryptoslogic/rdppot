import asyncio
import time
from threading import Thread

import aiorwlock
from recordclass import recordclass

"""
How this all works:

When a new RDP packet comes in from a remote host, we assign it it's own
dedicated VM IP to redirect all traffic to. This remote IP <-> internal VM IP
mapping is herein refered to as a Session.

For the duration of the session, all packets from the same remote host will be
relayed to the same VM.

Once a session expires (see the various timeout conditions below), the session
is destroyed along with any open TCP connections associated with it.

The reset_vm_callback then fires to allow the VM to be reset.

The StateManager class contains and manipulates the state of the entire system,
mostly asynchronously.
"""

RDP_PORT = 3389

# Time before we kill the VM after inactivity
TIMEOUT = 30 # seconds

# Time a sessions is allowed to last before we forcefully close it
# You might want to change this based on how many IPs you have on your host or how many VMs you have in your pool
SESSION_TIME_LIMIT = 300 # seconds

# Time that we prevent reconnections
BLACKLIST_TIMEOUT = 60 # seconds

# timestamp is the time the session was first established
# last_packet is the time a packet was last seen
# tasks is a list of PipeTasks associated with the session
SrvState = recordclass("SrvState", ["remote_ip", "timestamp", "last_packet", "tasks"])

# keep track of associated writers so we can close them all
PipeTask = recordclass("PipeTask", ["task", "writers"])

class StateManager:
	def __init__(self, balancer, reset_vm_callback, new_session_callback):
		# keeps track of what remote IP a server is servicing
		# False means there is a fresh VM ready for a new session
		# hosts are removed from this dict entirely during re-imaging
		self.srv_states = {}
		
		# TODO: lazy design, this should really be part of srv_states but then False can't
		# be used to denote a fresh VM
		self.user_datas = {}

		# maps remote IPs to internal IPs
		self.remote_sessions = {}

		# remote IPs that have connected recently
		self.temp_blacklist = set()

		# make sure srv_states and remote_sessions accesses stay coherent
		self.lock = aiorwlock.RWLock()
		
		# I noticed sometimes multiple connections would print the msg multiple times so this prevents the callback being ran more than once
		self.has_session_callbacked = False

		self.reset_vm_callback = reset_vm_callback
		self.new_session_callback = new_session_callback
		self.balancer = balancer
	
	async def add_new_host(self, internal_host, user_data=None):
		async with self.lock.writer_lock:
			# False means the host is ready
			self.srv_states[internal_host] = False
			self.user_datas[internal_host] = user_data
			print("Host {} added to pool: {}".format(internal_host, list(self.srv_states.keys())))
	
	async def _rebuild(self, internal_host, remote_host):
		def do_rebuild():
			self.reset_vm_callback(self.balancer, internal_host, remote_host, self.user_datas.get(internal_host))
		# We run the callback in a new thread to avoid the callback having to be async.
		# Otherwise, we'd block the event loop
		rebuild_thread = Thread(target=do_rebuild)
		rebuild_thread.start()

	async def _session_callback(self, addr, port, internal_host):
		def do_session_callback():
			self.new_session_callback(self.balancer, addr, port, internal_host, self.user_datas.get(internal_host))
		session_callback_thread = Thread(target=do_session_callback)
		session_callback_thread.start()

	async def _destroy_session_and_rebuild(self, remote_ip):
		async with self.lock.writer_lock:
			if remote_ip in self.remote_sessions:
				internal_host = self.remote_sessions[remote_ip]
				srv_state = self.srv_states[internal_host]
				for task in srv_state.tasks:
					# close any TCP sessions that might still be active
					for writer in task.writers:
						writer.close()
					task.task.cancel()
				del self.remote_sessions[remote_ip]
				del self.srv_states[internal_host]
				# (we can't del from user_datas yet since it's needed durning rebuild)
				self.temp_blacklist.add(remote_ip)
				asyncio.create_task(self._remove_from_blacklist_after_timeout(remote_ip))
			else:
				# TODO we could avoid this by putting the timeout tasks in the SrvState.tasks list
				print("The session was already destroyed (probably hit TIMEOUT before SESSION_TIME_LIMIT)")
				return
		
		await self._rebuild(internal_host, remote_ip)

	async def _destroy_session_after_limit(self, remote_ip):
		await asyncio.sleep(SESSION_TIME_LIMIT)
		
		print("Session for {} exceeded max duration.".format(remote_ip))
		
		await self._destroy_session_and_rebuild(remote_ip)

	async def _destroy_session_after_timeout(self, remote_ip):
		async with self.lock.reader_lock:
			if remote_ip in self.remote_sessions:
				internal_ip = self.remote_sessions[remote_ip]
			else:
				return
		
		await asyncio.sleep(TIMEOUT) # the earliest possible time that a timeout could occur
		
		# We keep checking to see if the TIMEOUT has expired.
		# If update_last_packet_time() happened in the mean time, the session
		# would have been extended, so we sleep and try again.
		while(True):
			async with self.lock.reader_lock:
				srv_state = self.srv_states.get(internal_ip)
			if not srv_state: # this would happen if SESSION_TIME_LIMIT was hit and the session is destroyed
				return
			timeout_remaining = TIMEOUT - (time.time() - srv_state.last_packet)
			if timeout_remaining <= 0:
				print("TIMEOUT reached, destroying session")
				await self._destroy_session_and_rebuild(remote_ip)
				return
			
			await asyncio.sleep(timeout_remaining)

	async def update_last_packet_time(self, internal_ip):
		"""
		This gets called every time some network activity happens, which will
		extend the TIMEOUT.
		"""
		#print("update_last_packet_time({})".format(internal_ip))
		async with self.lock.writer_lock:
			if self.srv_states.get(internal_ip):
				self.srv_states[internal_ip].last_packet = time.time()
				#print(self.srv_states[internal_ip].last_packet)

	async def _remove_from_blacklist_after_timeout(self, remote_ip):
		await asyncio.sleep(BLACKLIST_TIMEOUT)
		# Don't need to worry about locks here because there's nothing to race
		self.temp_blacklist.remove(remote_ip)
	
	async def get_internal_ip_for_remote_host(self, remote_ip):
		"""
		Used for routing incoming UDP packets, and new TCP sessions
		returns (internal_ip, timeout_remaining)
		"""
		# fast path - session already exists
		async with self.lock.reader_lock:
			internal_ip = self.remote_sessions.get(remote_ip)
		
		if internal_ip:
			await self.update_last_packet_time(internal_ip)
			return internal_ip
		
		# reject IPs that connected recently
		if remote_ip in self.temp_blacklist:
			print("Rejecting {} due to recent connection cooldown".format(remote_ip))
			return None
		
		# slow path - establish new session
		async with self.lock.writer_lock:
			internal_host = None
			available_count = 0
			
			# we could exit early from this loop, but then we couldn't print the
			# sessions available stat
			for ip, state in self.srv_states.items():
				if not state:
					available_count += 1
					internal_host = ip
			
			print("{}/{} sessions available".format(available_count, len(self.srv_states)))
			
			if internal_host:
				self.srv_states[internal_host] = SrvState(remote_ip, time.time(), time.time(), [])
				self.remote_sessions[remote_ip] = internal_host
				
				asyncio.create_task(self._destroy_session_after_limit(remote_ip))
				asyncio.create_task(self._destroy_session_after_timeout(remote_ip))

				return internal_host
		
		# TODO: Handle this better?
		print("Out of internal hosts!!! - rejecting connection")
		return None
	
	async def get_remote_ip_for_internal_host(self, internal_ip):
		"""
		used for routing outbound UDP responses
		"""
		async with self.lock.reader_lock:
			srv_state = self.srv_states.get(internal_ip)
		if srv_state is None: # this would happen if the session timed out
			return None
		await self.update_last_packet_time(internal_ip)
		return srv_state.remote_ip
	
	async def register_task(self, internal_ip, task):
		async with self.lock.writer_lock:
			self.srv_states[internal_ip].tasks.append(task)


"""
This method forwards data from a reader to a writer,
a pair of these are used to proxy TCP connections
from remote hosts to a VM.
"""
async def pipe(reader, writer, on_traffic):
	try:
		while not reader.at_eof():
			writer.write(await reader.read(2048))
			await on_traffic()
	except asyncio.CancelledError:
		print("Terminating pipe")
		pass
	finally:
		writer.close()


# inspired by https://stackoverflow.com/a/46422554/4454877
def handle_tcp_with_state(state):
	"""
	This function returns a handle_tcp function that uses the provided state object
	"""
	async def handle_tcp(reader, writer):
		addr, port = writer.get_extra_info('peername')
		
		internal_host = await state.get_internal_ip_for_remote_host(addr)
		
		if internal_host is None:
			writer.close()
			return
		
		# TODO: Should this be a lock? probably FIXME
		if not state.has_session_callbacked:
			state.has_session_callbacked = True
			await state._session_callback(addr, port, internal_host)

		print("Incoming TCP connection from {}, forwarding to {}".format(addr, internal_host))

		internal_reader, internal_writer = await asyncio.open_connection(internal_host, RDP_PORT)
		
		async def on_traffic():
			await state.update_last_packet_time(internal_host)
		
		pipe1 = pipe(reader, internal_writer, on_traffic)
		pipe2 = pipe(internal_reader, writer, on_traffic)
		
		# there must be some more idiomatic way of doing this
		async def the_task():
			await asyncio.gather(pipe1, pipe2)
		
		pipe_task = PipeTask(asyncio.create_task(the_task()), [writer, internal_writer])
		await state.register_task(internal_host, pipe_task)
	
	return handle_tcp


class UDPServerProtocol:
	def __init__(self, state):
		self.state = state

	def connection_made(self, transport):
		self.transport = transport
	
	def connection_lost(self, exc):
		pass

	def datagram_received(self, data, addr):
		remote_ip, port = addr
		async def forward_packet():
			internal_host = await self.state.get_internal_ip_for_remote_host(addr)
			print("Incoming UDP packet from {}, forwarding to {}".format(remote_ip, internal_host))
			self.transport.sendto(data, (internal_host, RDP_PORT))
		asyncio.create_task(forward_packet())


class Balancer:
	"""
	This class is the public interface to the balancing logic, and it basically
	bridges between the sync and async worlds.
	"""
	
	def __init__(self, reset_vm_callback, new_session_callback, listen_ip="0.0.0.0", listen_port=RDP_PORT):
		"""
		Spin up the TCP and UDP listener coroutines
		"""
		
		self.state = StateManager(self, reset_vm_callback, new_session_callback)
		self.loop = asyncio.get_event_loop()
		tcp_coro = asyncio.start_server(handle_tcp_with_state(self.state), listen_ip, listen_port, loop=self.loop)
		self.tcp_server = self.loop.run_until_complete(tcp_coro)

		udp_coro = self.loop.create_datagram_endpoint(
			lambda: UDPServerProtocol(self.state),
			local_addr=(listen_ip, listen_port))
		self.udp_transport, udp_protocol = self.loop.run_until_complete(udp_coro)

	def add_new_host(self, internal_ip, user_data=None):
		self.loop.create_task(self.state.add_new_host(internal_ip, user_data))

	def serve_forever(self):
		print("Serving until KeyboardInterrupt")
		
		try:
			self.loop.run_forever()
		except KeyboardInterrupt:
			pass

		# Close the server
		self.tcp_server.close()
		self.udp_transport.close()
		self.loop.run_until_complete(self.tcp_server.wait_closed())
		self.loop.close()
		
		print("Server closed")
