###################################################################
#
#   COMS3200- Assignment 2
#
#   Student Name: Thomas Sampey
#
###################################################################

import struct
import socket
import sys

PAYLOAD_SIZE = 1466
PACKET_SIZE = 1472

def payloads(string, pad=PAYLOAD_SIZE):
	"""
	payloads(string, pad) -> (Bytes)
	Takes a string / byte string and pads it
	to the correct padding length
	"""
	if isinstance(string, str):
		b_str = string.encode("UTF-8")
	else: 
		b_str = string
	if pad is not None:
		for i in range(len(string), pad):
			b_str += b'\0'
	return b_str


def construct_rush_packet(sequence,acknowlegement,flags, payload, debug):
	"""
	construct_rush_packet(sequence, acknowledgement, flags, payload, debug) -> (Bytes)
	Creates a RUSH packet with the given arguments

	"""
	seq = bin(sequence)
	ack = bin(acknowlegement)
	reserved = '00000000000'

	flags_Resv = flags + reserved
	binflags = bin(int(flags_Resv,2))
	intflags = int(binflags,2)


	rush_header = struct.pack('! HHH',sequence,acknowlegement,intflags)
	#construct and concat payload to header
	construct_payload = payloads(payload)
	rush_packet = rush_header + construct_payload

	
	#debug
	if(debug == 1):
		#print("-----")
		print('packet sequence: ' + str(sequence))
		#print("-----")
		print("-Rush Header-")
		#print(flags_Resv)
		#print(intflags)
		#print(rush_header)
		##print('--')
		#print('-Payload-')
		#print(construct_payload)
		##print(len(construct_payload))
		print('-Rush Packet-')
		print(rush_packet)
		print(len(rush_packet))
		#print("-----")

	return rush_packet

#extracts headers from rush packet
def rush_frame(data):
	"""
	rush_frame(data) -> (Int, Int, Int, Bytes)
	Reads and separates the header values and payload 
	of the RUSH frame
	"""

	seq, ack, flags = struct.unpack('! 2s 2s 2s',data[:6])
		
	seqInt = int.from_bytes(seq,byteorder='big')
	seq_binary = format(seqInt, '016b')

	ackInt = int.from_bytes(ack,byteorder='big')
	ack_binary = format(ackInt, '016b')
	flagsInt = int.from_bytes(flags,byteorder='big') >> 11
	flags_binary = format(flagsInt, '05b')

		
		#print(type(seq_binary))
		#print(type(ack_binary))
		#print(type(flags_binary))
		#print("-----")

		return seqInt, ackInt, flags_binary, data[6:]


#Creates Payloads from a received rush payload
#RETURNS a list of payloads
def payload_creator(payload):
	"""
	payload_creator(payload) -> (<List>)
	Reads a file and creates a list of payloads from the content within the file 
	that does not exceed the PAYLOAD_SIZE

	"""
	file = payload.rstrip(b'\x00').decode()
	#print(file)
	count = 0
	try:
		f = open(file, 'rb')
		s=f.read()
		rush_payloads = []
		while count <= len(s):
			rush_payloads.append(s[count:count + PAYLOAD_SIZE])
			count = count + PAYLOAD_SIZE

		#print(str(payloads[35]))
		#print(len(payloads))
		return rush_payloads

	except OSError as e:
		print("Could not find file")
	finally:
		f.close()

def isValidPacket(expected_client_seq_no, client_sequence_number, server_seq_no, client_ack_no, timeout_counter, data):
	"""
	isValidPacket(expected_client_seq_no, client_sequence_number, server_seq_no, client_ack_no, timeout_counter, data) -> (Boolean)
	Checks to see if the received packet is valid
	"""

	#print("Expected client sequence no type: ", expected_client_seq_no, "Client_sequence number: ", client_sequence_number)
	
		return (isValidPacketLength(data)) and (isValidAckNo(server_seq_no, client_ack_no)) and (isValidSequenceNo(expected_client_seq_no, client_sequence_number))
	#Add sequence number and packet data checks

def isValidPacketLength(rush_packet):
	"""
	isValidPacketLength(rush_packet) -> (Boolean)
	Checks to see if the packet length is the correct size
	"""
	if len(rush_packet) == PACKET_SIZE:
		return True
	else:
		return False

def isValidSequenceNo(client_expected_next_seq_number, client_current_seq_number):
	"""
	isValidSequenceNo(client_expected_next_seq_number, client_current_seq_number) -> (Boolean)
	Checks to see if the expected sequence number matches the sequence number received from the packet
	"""
	
	if client_expected_next_seq_number == client_current_seq_number:
		#print("Failed Sequence No - Client current Seq number: " + str(client_current_seq_number) + " client Expected next seq number: " + str(client_expected_next_seq_number))
		return True
	else:
		return False

def isValidAckNo(server_seq_number, client_ack_number):
	"""
	isValidAckNo(server_seq_number, client_ack_number) -> (Boolean)
	Checks to see if the acknowledgement number is correct
	"""
	#-1 due to it being the packet just sent
	if ((server_seq_number - 1) == client_ack_number):
		
		return True
	else:
		print("Failed ACK No" + str(server_seq_number) + " " + str(client_ack_number))
		return False 
		
def isValidPayload(payload):
	"""
	isValidPayload(payload) -> (Boolean)
	Checks to see if the payload is not empty
	"""
	print("payload:",[int_to_str(payload.decode())], " l: ", len(int_to_str(payload.decode())))
	return int_to_str(payload.decode()) != ""


def int_to_str(integer, size=PAYLOAD_SIZE):
	"""
	int_to_str(integer, size) -> (Int)
	Removes padding from packet
	"""
    return integer.rstrip(b'\x00').decode("UTF-8")

def main():
	"""
	Main method
	Handles the receiving of packets and initialising of variables
	"""

	server_seq_no = 1
	server_ack_no = 0

	client_seq_no = 0
	client_ack_no = 0
	client_prev_seq_no = 0

	STATE = "NONE"
	SUBSTATE = "NONE"

	#counts amount of timeouts.
	timeout_counter = 0

	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.bind(('127.0.0.1',0)) #REPLACE WITH 0 FOR PORT!!!!!!!!!!!!!!!!!!!
		print(s.getsockname()[1])
		sys.stdout.flush()
		
		#connection
		while True:
			expected_client_seq_no = 0
			try:
				print('----START OF ITERATION----')

				s.settimeout(10)
				#Retrieve 1st Data from Client
				data, addr = s.recvfrom(PACKET_SIZE)

				#update expected client sequence number
				
				
				#Get Sequence No, Acknowledgement and Rush Data 
				client_seq, client_ack,flags, client_rush_data = rush_frame(data) #incoming packet
				#set Clients Sequence and ACK numbers and previous sequence number
				client_seq_no = client_seq
				client_ack_no = client_ack

				#expected client sequence number
				expected_client_seq_no = 2
				
				

				
				#No. packets received from client
				

				#check to see if first packet is not empty, flag is GET and Client Seq is 1
				if flags == "00100" and client_seq_no == 1: 
					print("entered")
					#return Payload from file given from Clients initial GET packet 
					payloads = payload_creator(client_rush_data)
					print("Amount of packets to send: " + str(len(payloads)))
				
					#Data Sending and Receiving Loop
					while True:
						try:
							#Create Rush Data Packet and Sends it
							rush_packet = construct_rush_packet(server_seq_no, 0, '00010',payloads[server_seq_no - 1],0) 
							s.sendto(rush_packet,addr)

							#increment server sequence number
							server_seq_no = server_seq_no + 1
						
							print('-----')
							print("next Packet to Send: " +str(server_seq_no))

							#Sets socket timeout to 3 seconds
							s.settimeout(3)
							
							#Checks client response for packet thats just been sent
							data, addr = s.recvfrom(PACKET_SIZE)	
							client_seq, client_ack, client_flags, client_rush_data = rush_frame(data) #incoming packet

							#save the client sequence number and Ack
							client_seq_no = client_seq
							client_ack_no = client_ack

							
							print("Server Sequence Number: " + str(server_seq_no-1))
							print("Client Info: seq: "+str(client_seq_no) +" ACK: "+str(client_ack_no)+" Flags: "+str(client_flags))
							
							
							print("Client Sequence Number: " + str(client_seq_no))

							print("--")
							print("Valid Packet Length: " + str(isValidPacketLength(data)))
							print("Valid Sequence Number: " + str(isValidSequenceNo(expected_client_seq_no, client_seq_no)))
							#print("expected: "+str(expected_client_seq_no))
							#print("Valid Acknowledgement Number: " + str(isValidAckNo(server_seq_no, client_ack_no)))
							print('-----')
							
							#Checking if last packet has been sent
							if server_seq_no > len(payloads) and client_flags == "10010" and isValidPacket(expected_client_seq_no, client_seq, server_seq_no, client_ack_no, timeout_counter, data):
								print('Final Sent Packet No: '+str(server_seq_no))
								
								#expected client sequence no increments unless theres a timeout 
								expected_client_seq_no = expected_client_seq_no + 1
								STATE = "END_HANDSHAKE"
								SUBSTATE = "SEND_FIN"
								break
							
							#Check to see if Valid Packet and Flags that are set

							elif client_flags == "10010"  and isValidPacket(expected_client_seq_no, client_seq, server_seq_no, client_ack_no, timeout_counter, data): #ACK
								#expected client sequence no increments unless theres a timeout 
								
								expected_client_seq_no = expected_client_seq_no + 1
								
								print("stuff: "+str(expected_client_seq_no)+" : " + str(client_seq_no))
								continue
							
							elif client_flags == "01010" and isValidPacket(expected_client_seq_no, client_seq, server_seq_no, client_ack_no, timeout_counter, data): #Invalid Packet: #and is valid #NAK
								
								print("NAK")
								#decrement to previous server sequence number 
								server_seq_no = server_seq_no - 1
								#expected client sequence no increments unless theres a timeout 
								expected_client_seq_no = expected_client_seq_no + 1


							elif not isValidPacket(expected_client_seq_no, client_seq, server_seq_no, client_ack_no, timeout_counter, data) or client_flags != "01010" or client_flags != "10010": #Invalid Packet
								#decrement to previous server sequence number 
								server_seq_no = server_seq_no - 1
								print("server sequence no: ", server_seq_no, "\nExpected Client sequence number: ", expected_client_seq_no,"client sequence number: ", client_seq_no)
								
								print("Invalid Packet Received")

								
							#print('END OF LOOP - SERVER SEQUENCE NO: '+str(server_seq_no))

						except KeyboardInterrupt as e:
							sys.exit()
						except socket.timeout as f:
							print("Socket timed out")
							server_seq_no = server_seq_no - 1
							#expected_client_seq_no = expected_client_seq_no - 1
							#update timeout counter
							timeout_counter = timeout_counter + 1
						except:
							#Resend Packet 
							pass

							#decrement server sequence number to send previous packet
							
						finally:
							pass

				if STATE == "END_HANDSHAKE":
					#print("END HANDSHAKE")
					#End Handshake Loop
					while True:
						try:
							if SUBSTATE =="SEND_FIN":

								print('SEND_FIN: ' + str(server_seq_no))

								#Construct and Send FIN Packet
								FIN_packet = construct_rush_packet(server_seq_no,0,'00001','',0)
								s.sendto(FIN_packet,addr)
								
								#increment server sequence number
								server_seq_no = server_seq_no + 1

								#Update SUBSTATE
								SUBSTATE = "SEND_FINACK"

								#Set socket timeout to 3 seconds
								s.settimeout(3)
								
								#Retrieve Response from Client
								data, addr = s.recvfrom(PACKET_SIZE)	
								client_seq ,client_ack,client_flags, client_rush_data = rush_frame(data) 
								
								#Updata received client packet count
							
							
								#save the client sequence number and Ack
								client_seq_no = client_seq
								client_ack_no = client_ack
								client_flags_no = client_flags
								
								print("sequence number: ", client_seq_no," expected sequence no: ", expected_client_seq_no)
								print("Valid Sequence Number: " + str(isValidSequenceNo(expected_client_seq_no, client_seq_no)))
							
								print('-----')

							#print("Client Packet Flags: " + str(client_flags) + " SUBSTATE: " + str(SUBSTATE))
							elif client_flags == "10001" and SUBSTATE == "SEND_FINACK" and isValidPacket(expected_client_seq_no, client_seq, server_seq_no, client_ack_no, timeout_counter, data):
								
								#print("Valid Sequence Number: " + str(isValidSequenceNo(expected_client_seq_no, client_seq_no)))

								#increment server sequence number for FIN 
								#CASE: FIN is is not FIN/ACK = RESEND FIN  
								

								#Construct and Send FIN/ACK 
								FINACK_packet = construct_rush_packet(server_seq_no,client_seq_no,'10001','',0)
								s.sendto(FINACK_packet,addr)

								server_seq_no = server_seq_no + 1

								#End connection
								return

							elif client_flags != "10001" or not isValidPacket(expected_client_seq_no, client_seq, server_seq_no, client_ack_no, timeout_counter, data):
								SUBSTATE = "SEND_FIN"
								print("Invalid Flags")
								print("Client FLAGS: "+str(client_flags))
						
						except KeyboardInterrupt as e:
							sys.exit()
						
						except:
							SUBSTATE = "SEND_FIN"
							timeout_counter = timeout_counter + 1

							#decrement sequence number to resend in packet
							server_seq_no = server_seq_no - 1
							#expected_client_seq_no = expected_client_seq_no - 1
							print("Handshake Timeout exception")
						
						finally:
							pass
			except KeyboardInterrupt as e:
				sys.exit()

			except:
				print("exception")
			finally:
				pass

					
	except KeyboardInterrupt as e:
		sys.exit()

	finally:
		s.close()


if __name__ == '__main__':
    main()