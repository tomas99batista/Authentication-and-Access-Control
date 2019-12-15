import asyncio
import json
import base64
import argparse
import coloredlogs, logging
import os
import ssl
import random
import string
import json
import getpass
import sys
import cryptography.hazmat.primitives.serialization as serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.asymmetric import dh, rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric import padding as pdr
from cryptography import x509
from cc import CCModule

logger = logging.getLogger('root')

STATE_CONNECT = 0
STATE_NEGOTIATING = 1
STATE_OPEN = 2
STATE_DATA = 3
STATE_CLOSE = 4

# duas cifras simétricas (AES e Salsa20)
# dois modos de cifra (CBC e GCM)
# dois algoritmos de sintese (SHA-256 e SHA-512)

class ClientProtocol(asyncio.Protocol):
	"""
	Client that handles a single client
	"""
	def __init__(self, file_name, loop, mode):
		"""
		Default constructor
		:param file_name: Name of the file to send
		:param loop: Asyncio Loop to use
		"""
		self.file_name = file_name
		self.loop = loop
		self.state = STATE_CONNECT  # Initial State
		self.buffer = ''  # Buffer to receive data chunks
		self.CCModule = CCModule()
		# Estes values vao ser preenchidos apos troca de mensagem
		self.algoritmo = None   	# Algoritmo a usar
		self.modo = None        	# Modo de cifra a usar
		self.sintese = None     	# Função de cifra a usar
		self.iv = None
		self.protocols = {
			'cifras': ['CAST5', 'AES'],
			'modos': ['ECB', 'CBC'],
			'sinteses': ['MD5', 'SHA-256']
		}
		# ==================================================
		# Key + DH
		self.key = None				# Key
		self.cli_priv_key = None	# Key privada do cliente
		self.cli_pub_key = None		# Key publica do cliente
		# RSA
		self.rsa_cli_pub_key = None		# Key publica do rsa
		self.rsa_cli_priv_key = None	# Key privada do rsa
		# Cert
		self.server_cert_pub_key = None	# Key publica do cert do server
		# ==================================================
		self.count = 0
		if mode == None or (mode.upper() != 'PWD' and mode.upper() != 'CC'):
			logger.warning('bad usage!!!')
			logger.info('\tEX: python3 client.py *FILE* -mode *MODO*')
			logger.info('\tMODO: -mode cc for cc authentication OR -mode pwd for password authenticantion')
			exit()
		if mode.upper() == 'PWD': self.mode = 'PWD'
		if mode.upper() == 'CC': self.mode = 'CC'

	# Quando a connection é efectuada, manda para la uma mensagem AGREEMENT c/ a cifra, o modo e a sintese a usar
	def connection_made(self, transport): # -> None:
		"""
		Called when the client connects.

		:param transport: The transport stream to use for this client
		:return: No return
		"""
		self.transport = transport

		logger.debug('Connected to Server')

		# Vai enviar uma mensagem de agreement
		self.state = STATE_NEGOTIATING
		self.set_agreement()

	def data_received(self, data: str): # -> None:
		"""
		Called when data is received from the server.
		Stores the data in the buffer

		:param data: The data that was received. This may not be a complete JSON message
		:return:
		"""
		logger.debug('Received: {}'.format(data))
		try:
			self.buffer += data.decode()
		except:
			logger.exception('Could not decode data from client')

		idx = self.buffer.find('\r\n')

		while idx >= 0:  # While there are separators
			frame = self.buffer[:idx + 2].strip()  # Extract the JSON object
			self.buffer = self.buffer[idx + 2:]  # Removes the JSON object from the buffer

			self.on_frame(frame)  # Process the frame
			idx = self.buffer.find('\r\n')

		if len(self.buffer) > 4096 * 1024 * 1024:  # If buffer is larger than 4M
			logger.warning('Buffer to large')
			self.buffer = ''
			self.transport.close()

	def on_frame(self, frame: str):# -> None:
		"""
		Processes a frame (JSON Object)

		:param frame: The JSON Object to process
		:return:
		"""

		logger.debug("Frame: {}".format(frame))
		try:
			message = json.loads(frame)
		except:
			logger.exception("Could not decode the JSON message")
			self.transport.close()
			return

		# Recebe uma secure message
		if message['type'] == 'SECURE_MESSAGE':
			pl = base64.b64decode(message['payload'])
			mac = base64.b64decode(message['HMAC'])
			message = json.loads(self.decript(pl, mac))
		
		logger.info(f'New message: {message}')
		
		mtype = message.get("type", "").upper()
		
		# Cli and SV conhecem o que estao a usar
		if mtype == 'AGREEMENT_OK':
			self.parameters_generator()
		
		# Recebe chave publica do server, que vai ser usada para gerar as suas
		elif mtype == 'PUBLIC_SV_KEY':
			self.key_generator(message)
		
		# Authenticate server
		elif mtype == 'SERVER_AUTH_REPLY':
			self.auth_server(message)

		# Recebe o challenge (que pediu anteriormente)
		elif mtype == 'CHALLENGE_PASSWORD':
			self.respond_challenge_password(message)

		# Recebe o challengee para o cc
		elif mtype == 'CHALLENGE_CC':
			self.respond_challenge_cc(message)

		# Authenticated ok
		elif mtype == 'AUTHENTICATION_OK':
			self.send_open()

		# SV and Cli both have the key now
		elif mtype == 'OK': # Server replied OK. We can advance the state
			if self.state == STATE_OPEN:
				logger.info("Channel open")
				self.send_file(self.file_name)
			else:
				logger.warning("Ignoring message from server")
			return
		elif mtype == 'ERROR':
			logger.warning("Got error from server: {}".format(message.get('data', None)))
		else:
			logger.warning("Invalid message type")

	# Request username and password
	def respond_challenge_password(self, message: str):
		logger.info('Got nonce, going to respond to challenge')
		self.challenge_nonce = base64.b64decode(message['nonce'])
		print('Use user, pwd, secret (flavia, flavia, galinha) to try a user that its allowed to get the files')
		print('Use user, pwd, secret (tomas, tomas, ovo) to try a user that its NOT allowed to get the files')
		username = input('Username: ')
		password = getpass.getpass('Password:')
		question = str(input('Qual e coisa qual e ela...: '))
		pwd = password.encode() + self.challenge_nonce

		hasher = hashes.Hash(hashes.SHA256(), default_backend())
		hasher.update(pwd)
		digest = hasher.finalize()
		signed_pw = self.rsa_cli_priv_key.sign(digest, 
						pdr.PSS(mgf=pdr.MGF1(hashes.SHA256()), salt_length=pdr.PSS.MAX_LENGTH),
						utils.Prehashed(hashes.SHA256()))

		payload, mac = self.encript(str.encode(json.dumps({'type': 'CHALLENGE_RESPONSE_PASSWORD', 
									'username': username, 
									'password': base64.b64encode(signed_pw).decode('utf-8'),
									'question': question})))
		msg = {
			'type': 'SECURE_MESSAGE',
			'payload': base64.b64encode(payload).decode('utf-8'),
			'HMAC': base64.b64encode(mac).decode('utf-8')
		}
		# Define o state como open, aka vai começar a enviar files
		# Sinto que isto n deve estar aqui mas ok, talvez ate deva, o problema é
		# quando for preciso trocar a cifra, adiante, ele envia a sua chave e a seguir
		# quando receber a proxima mensagem ja é envia files bota e vira
		self.state = STATE_OPEN
		self._send(msg)

	# Ve a resposta a challenge que recebeu
	def respond_challenge_cc(self, message: str):
		self.challenge_nonce_cc = base64.b64decode(message['nonce'])
		self.CA_cert_CC_priv_key = self.CCModule.privateKeyCC()
		
		pk = self.CCModule.privateKeyCC()
		signed_nonce = self.CCModule.signature(pk,self.challenge_nonce_cc)
		# Resposta ao pedido de challenge
		payload, mac = self.encript(str.encode(json.dumps({'type': 'CHALLENGE_RESPONSE_CC', 
															'nonce': base64.b64encode(signed_nonce).decode('utf-8')})))
		
		
		msg = {
			'type': 'SECURE_MESSAGE',
			'payload': base64.b64encode(payload).decode('utf-8'),
			'HMAC': base64.b64encode(mac).decode('utf-8')
		}
		# Define o state como open, aka vai começar a enviar files
		# Sinto que isto n deve estar aqui mas ok, talvez ate deva, o problema é
		# quando for preciso trocar a cifra, adiante, ele envia a sua chave e a seguir
		# quando receber a proxima mensagem ja é envia files bota e vira
		self.state = STATE_OPEN
		self._send(msg)

	# Will send what to use (cifra, sintese, modo) to the sv
	def set_agreement(self): # -> None:
		self.algoritmo = self.protocols.get('cifras')[random.randint(0, 1)]
		self.modo = self.protocols.get('modos')[random.randint(0, 1)]
		self.sintese = self.protocols.get('sinteses')[random.randint(0, 1)]
		if self.algoritmo == 'AES':
			self.iv = os.urandom(16)
		elif self.algoritmo == 'CAST5':
			self.iv = os.urandom(8)
		# Envia mensagem a dizer quais sao os valores
		message = {'type': 'AGREEMENT',
					'algoritmo': self.algoritmo,
					'modo': self.modo,
					'sintese': self.sintese,
					'iv' : base64.b64encode(self.iv).decode('utf-8')}
		self._send(message)

	def send_open(self): # -> None
		txt = str.encode(json.dumps({'type': 'OPEN', 'file_name': self.file_name }))
		payload, mac = self.encript(txt)
		msg = {
			'type': 'SECURE_MESSAGE',
			'payload': base64.b64encode(payload).decode('utf-8'),
			'HMAC': base64.b64encode(mac).decode('utf-8')
		}
		self._send(msg)
		self.state = STATE_OPEN

	def encript(self, txt):
		cipher = None   
		block_size = 0
		# Algoritmo
		if self.algoritmo == 'AES':    
			alg = algorithms.AES(self.key)
			block_size = alg.block_size
		elif self.algoritmo == 'CAST5':
			alg = algorithms.CAST5(self.key)
			block_size = alg.block_size
		# Modo de encriptografar
		if self.modo == 'ECB':
			mod = modes.ECB()
		elif self.modo == 'CBC':
			mod = modes.CBC(self.iv)
		cipher = Cipher(alg, mod, backend=default_backend())
		# Sintese
		if self.sintese == 'SHA-256': 
			sints = hashes.SHA256()
		elif self.sintese == 'MD5':
			sints = hashes.MD5()
		encryptor = cipher.encryptor()
		# Text
		msg = base64.b64encode(txt)
		padder = padding.PKCS7(block_size).padder()
		padded_data = padder.update(msg) + padder.finalize()
		# Encrypted text
		ct = encryptor.update(padded_data) + encryptor.finalize() 
		# HMAC
		h = hmac.HMAC(self.key, sints, backend=default_backend())
		h.update(ct)
		mac = h.finalize()
		return ct, mac

	def decript(self, ct, mac):
		backend = default_backend()
		cipher = None   
		block_size = 0
		# Algoritmo
		if self.algoritmo == 'AES':
			alg = algorithms.AES(self.key)	
			block_size = alg.block_size
		elif self.algoritmo == 'CAST5':
			alg = algorithms.CAST5(self.key)
			block_size = alg.block_size
		# Modo de encriptografar
		if self.modo == 'ECB':  
			mod = modes.ECB()
		elif self.modo == 'CBC':
			mod = modes.CBC(self.iv)
		cipher = Cipher(alg, mod, backend=default_backend())
		# Sintese
		if self.sintese == 'SHA-256': 
			sints = hashes.SHA256()
		elif self.sintese == 'MD5':
			sints = hashes.MD5()
		# Decryptor
		decryptor = cipher.decryptor()
		# Padder
		unpadder = padding.PKCS7(block_size).unpadder()
		# Hmac
		h = hmac.HMAC(self.key, sints, backend=default_backend())
		# VERIFICAR SE O HMAC CONTINUA O MESMO
		h.update(ct)
		h.verify(mac)
		padded_data = decryptor.update(ct) + decryptor.finalize()
		data = unpadder.update(padded_data) + unpadder.finalize()
		clean_data = base64.b64decode(data)
		return clean_data

	# Will send the keys to the server
	def parameters_generator(self): # -> None
		logger.info('Agreement: CHECK')

		parameters = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())
		# Calcular a privada
		self.cli_priv_key = parameters.generate_private_key()
		# Calcular a pública
		self.cli_pub_key = self.cli_priv_key.public_key()

		cli_pub_key_bytes = self.cli_pub_key.public_bytes(
			serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
		)
		# Primos
		p = parameters.parameter_numbers().p
		g = parameters.parameter_numbers().g

		message = {'type': 'PARAMETERS_GENERATOR',
					'cli_pub_key': base64.b64encode(cli_pub_key_bytes).decode('utf-8'),
					'p': p,
					'g': g,
					}
		self._send(message)

	def key_generator(self, message):
		sv_pub_key_bytes = base64.b64decode(message['sv_pub_key'])
		sv_pub_key = serialization.load_der_public_key(sv_pub_key_bytes, backend=default_backend())

		shared_key = self.cli_priv_key.exchange(sv_pub_key)
		# Perform key derivation.
		self.key = HKDF(
			algorithm=hashes.SHA256(),
			length=16,
			salt=None,
			info=b'handshake data',
			backend=default_backend()
		).derive(shared_key)

		# Enviar pedido de autenticação do server
		self.server_auth_nonce = os.urandom(16)
		txt = str.encode(json.dumps({'type': 'SERVER_AUTH_REQ', 'nonce': base64.b64encode(self.server_auth_nonce).decode('utf-8') }))
		payload, mac = self.encript(txt)
		msg = {
			'type': 'SECURE_MESSAGE',
			'payload': base64.b64encode(payload).decode('utf-8'),
			'HMAC': base64.b64encode(mac).decode('utf-8')
		}
		self._send(msg)

	# Authenticate the server
	def auth_server(self, message):
		# * Validar o nonce assinado recebido com o nonce que tem em memoria (self) usando 
		# * a chave publica do certificado do servidor
		# Recebido
		nonce = base64.b64decode(message['nonce']) # Nonce recebido, que vai ser comparado ao nonce que tem em memoria
		server_cert_bytes = base64.b64decode(message['server_cert'])
		self.server_cert = x509.load_der_x509_certificate(server_cert_bytes, backend=default_backend())
		# ? Carrega root ca cert
		with open("certs/CA_Certs/Root_CA.crt", "rb") as root_certs:
			self.root_ca_certs = x509.load_pem_x509_certificate(root_certs.read(), default_backend())		
		# Key publica do certificado do servidor
		self.server_cert_pub_key = self.server_cert.public_key()
		
		# Calculado
		hasher = hashes.Hash(hashes.SHA256(), default_backend())
		hasher.update(self.server_auth_nonce)
		digest = hasher.finalize()
		try:						# Recebido vs Calculado
			self.server_cert_pub_key.verify(nonce, digest,
					pdr.PSS(mgf=pdr.MGF1(hashes.SHA256()), salt_length=pdr.PSS.MAX_LENGTH),
					utils.Prehashed(hashes.SHA256()))
			logger.info('Server Nonce Authenticated')
		except:
			# envia erro
			logger.warn('Server Nonce Authentication failed')
			self._send({'type': 'ERROR', "message": "See client"})
		
		# * Constroi a chain do server e root cert e valida cada um
		flag_s, chain_server = self.CCModule.issuers_sv(self.server_cert)

		self.CCModule.verify_server(chain_server)

		# ! Se tudo correu bem pede challenge_request // CC AUTH, depois depende
		if self.mode == 'PWD': self.challenge_request_password()
		elif self.mode == 'CC': self.challenge_request_cc()
		# ! Se tudo correr mal fecha conexão
		else:
			logger.info('Server not authenticated!')
			self._send({"type": "ERROR", "message": "See client"})

	# Pede challenge request (o nonce) e manda o certificado do cc
	def challenge_request_cc(self):
		self.CA_cert_CC = self.CCModule.certificate

		ca_cert_cc_bytes = self.CA_cert_CC.public_bytes(serialization.Encoding.DER)
		txt = str.encode(json.dumps({'type': 'CHALLENGE_REQUEST_CC', 'CA_cert': base64.b64encode(ca_cert_cc_bytes).decode('utf-8')}))
		payload, mac = self.encript(txt)
		msg = {
			'type': 'SECURE_MESSAGE',
			'payload': base64.b64encode(payload).decode('utf-8'),
			'HMAC': base64.b64encode(mac).decode('utf-8')
		}
		self._send(msg)


	# Pede challenge request, pede nonce
	def challenge_request_password(self):
		# RSA PART
		self.rsa_cli_priv_key = rsa.generate_private_key(public_exponent=65537,
											   key_size=2048,
											   backend=default_backend())
		self.rsa_cli_pub_key = self.rsa_cli_priv_key.public_key()

		rsa_cli_pub_key_bytes = self.rsa_cli_pub_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
		txt = str.encode(json.dumps({'type': 'CHALLENGE_REQUEST_PASSWORD', 
									'RSA_CLI_PUB_KEY': base64.b64encode(rsa_cli_pub_key_bytes).decode('utf-8')}))
		payload, mac = self.encript(txt)
		msg = {
			'type': 'SECURE_MESSAGE',
			'payload': base64.b64encode(payload).decode('utf-8'),
			'HMAC': base64.b64encode(mac).decode('utf-8')
		}
		self._send(msg)

	def connection_lost(self, exc):
		"""
		Connection was lost for some reason.
		:param exc:
		:return:
		"""
		logger.info('The server closed the connection')
		self.loop.stop()

	def send_file(self, file_name: str): # -> None:
		logger.info('Sending file: {}'.format(file_name))
		"""
		Sends a file to the server.
		The file is read in chunks, encoded to Base64 and sent as part of a DATA JSON message
		:param file_name: File to send
		:return:  None
		"""
		with open(file_name, 'rb') as f:
			message = {'type': 'DATA', 'data': None}
			read_size = 16 * 60
			
			contador = 0
			finish = False
			# PARA ALTERAR O THRESHOLD MUDAR ESTE VALOR
			threshold = 1000000000000000000000000000000
			while True:
				data = f.read(16 * 60)
				if contador == threshold + self.count:
					self.count += contador
					self.parameters_generator()
					break
				elif contador < threshold + self.count:			
					message['data'] = base64.b64encode(data).decode('utf-8')
					txt = str.encode(json.dumps(message))
					payload, mac = self.encript(txt)
					msg = {
						'type': 'SECURE_MESSAGE',
						'payload': base64.b64encode(payload).decode('utf-8'),
						'HMAC': base64.b64encode(mac).decode()
						}
					self._send(msg)	
				contador += 1

				if len(data) != read_size:
					finish = True
					break
			
			if finish:
				# Encriptar o close
				txt = str.encode(json.dumps({'type': 'CLOSE'}))
				payload, mac = self.encript(txt)
				msg = {
					'type': 'SECURE_MESSAGE',
					'payload': base64.b64encode(payload).decode('utf-8'),
					'HMAC': base64.b64encode(mac).decode()
				}
				self._send(msg)
				logger.info("File transferred. Closing transport")
				self.transport.close()

	def _send(self, message: str) -> None:
		"""
		Effectively encodes and sends a message
		:param message:
		:return:
		"""
		logger.info("Send: {}".format(message))

		message_b = (json.dumps(message) + '\r\n').encode()
		self.transport.write(message_b)

def main():
	parser = argparse.ArgumentParser(description='Sends files to servers.')
	parser.add_argument('-v', action='count', dest='verbose',
						help='Shows debug messages',
						default=0)
	parser.add_argument('-s', type=str, nargs=1, dest='server', default='127.0.0.1',
						help='Server address (default=127.0.0.1)')
	parser.add_argument('-p', type=int, nargs=1,
						dest='port', default=5000,
						help='Server port (default=5000)')

	parser.add_argument(type=str, dest='file_name', help='File to send')
	parser.add_argument('-mode', dest='mode', help='-mode CC | PWD')

	args = parser.parse_args()
	file_name = os.path.abspath(args.file_name)
	level = logging.DEBUG if args.verbose > 0 else logging.INFO
	port = args.port
	server = args.server
	mode = args.mode
	coloredlogs.install(level)
	logger.setLevel(level)

	logger.info("Sending file: {} to {}:{} LogLevel: {}".format(file_name, server, port, level))

	loop = asyncio.get_event_loop()
	coro = loop.create_connection(lambda: ClientProtocol(file_name, loop, mode),
								  server, port)
	loop.run_until_complete(coro)
	loop.run_forever()
	loop.close()

if __name__ == '__main__':
    	main()
