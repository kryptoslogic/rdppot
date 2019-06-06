from balancer import Balancer
import time

def reset_vm_callback(balancer, host_ip, remote_host, user_data):
	print("resetting {} (user_data: {})".format(host_ip, user_data))
	time.sleep(10)
	print("Done resetting {}".format(host_ip))
	balancer.add_new_host(host_ip)

balancer = Balancer(reset_vm_callback, listen_port=8888)

SRV_POOL = ["google.com", "example.com", "twitter.com"]

for srv in SRV_POOL:
	balancer.add_new_host(srv, user_data=srv.upper())

balancer.serve_forever()
