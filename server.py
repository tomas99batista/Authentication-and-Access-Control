import asyncio
import json
import base64
import argparse
import coloredlogs, logging
import os
import random
import string
import json
import re
import cryptography.hazmat.primitives.serialization as serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import padding
from aio_tcpserver import tcp_server
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric import padding as pdr
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cc import CCModule

backend = default_backend()

logger = logging.getLogger("root")

STATE_CONNECT = 0
STATE_NEGOTIATING = 1
STATE_OPEN = 2
STATE_DATA = 3
STATE_CLOSE = 4

# duas cifras simétricas (AES e Salsa20)
# dois modos de cifra (CBC e GCM)
# dois algoritmos de sintese (SHA-256 e SHA-512)

# GLOBAL
storage_dir = "files"


class ClientHandler(asyncio.Protocol):
	def __init__(self, signal):
		"""
		Default constructor
		"""
		self.signal = signal
		self.state = 0
		self.file = None
		self.file_name = None
		self.file_path = None
		self.storage_dir = storage_dir
		self.buffer = ""
		self.peername = ""
		# ============================================================		
		# Passwords
		self.users = {'tomas': ['tomas', 'N', 'ovo'], 'flavia': ['flavia', 'Y', 'galinha']}
		# ============================================================
		# Estes values vao ser preenchidos apos troca de mensagem
		self.algoritmo = None   # Algoritmo a usar
		self.modo = None        # Modo de cifra a usar
		self.sintese = None     # Função de cifra a usar
		self.iv = None			# IV
		self.protocols = {
			'cifras': ['CAST5', 'AES'],
			'modos': ['ECB', 'CBC'],
			'sinteses': ['MD5', 'SHA-256']
		}
		# ============================================================
		self.CCModule = CCModule()		
		# Key + DH
		self.key = None				# Key
		self.sv_priv_key = None		# Key privada do cliente
		self.sv_pub_key = None		# Key publica do cliente
		# RSA
		self.rsa_cli_pub_key = None		# Key publica do rsa do client
		self.rsa_sv_priv_key = None		# Key privada do rsa
		self.rsa_sv_pub_key = None		# Key privada do rsa
		# Cert
		self.server_cert_priv_key = None	# Key privada do cert
		self.server_cert_pub_key = None		# Key publica do cert
		# ============================================================

	def connection_made(self, transport):  # -> None:
		"""
		Called when a client connects

		:param transport: The transport stream to use with this client
		:return:
		"""
		self.peername = transport.get_extra_info("peername")
		logger.info("\n\nConnection from {}".format(self.peername))
		self.transport = transport
		self.state = STATE_CONNECT

	def data_received(self, data: bytes):  # -> None:
		"""
		Called when data is received from the client.
		Stores the data in the buffer

		:param data: The data that was received. This may not be a complete JSON message
		:return:
		"""
		logger.debug("Received: {}".format(data))
		try:
			self.buffer += data.decode()
		except:
			logger.exception("Could not decode data from client")

		idx = self.buffer.find("\r\n")

		while idx >= 0:  # While there are separators
			logger.debug("Index: {}".format(idx))
			frame = self.buffer[: idx + 2].strip()  # Extract the JSON object
			self.buffer = self.buffer[
				idx + 2:
			]  # Removes the JSON object from the buffer

			self.on_frame(frame)  # Process the frame
			idx = self.buffer.find("\r\n")

		if len(self.buffer) > 4096 * 1024 * 1024:  # If buffer is larger than 4M
			logger.warning("Buffer to large")
			self.buffer = ""
			self.transport.close()

	def on_frame(self, frame: str):  # -> None:
		"""
		Called when a frame (JSON Object) is extracted

		:param frame: The JSON object to process
		:return:
		"""
		logger.debug("Frame: {}".format(frame))

		try:
			message = json.loads(frame)
		except:
			logger.exception("Could not decode JSON message: {}".format(frame))
			self.transport.close()
			return

		# Recebe uma secure message
		if message['type'] == 'SECURE_MESSAGE':
			pl = base64.b64decode(message['payload'])
			mac = base64.b64decode(message['HMAC'])
			message = json.loads(self.decript(pl, mac))
		logger.info(f'New message: {message}')

		mtype = message.get("type", "").upper()

		# Recebe a cifra, modo e sintese
		if mtype == "AGREEMENT":
			ret = self.agreement(message)
		# Recebe a chave
		elif mtype == "PARAMETERS_GENERATOR":
			ret = self.keys_exchange(message)
		# A troca de chaves está ok, passar ao desafio-resposta
		elif mtype == 'CHALLENGE_REQUEST_PASSWORD':
			ret = self.send_challenge_password(message)

		# O client envia pedido de challenge com cc, enviando o seu certificado 
		elif mtype == 'CHALLENGE_REQUEST_CC':
			ret = self.send_challenge_cc(message)

		# O client envia username e password
		elif mtype == 'CHALLENGE_RESPONSE_PASSWORD':
			ret = self.process_challenge_response_password(message)

		# O cliente enviou o nonce assinado com 
		elif mtype == 'CHALLENGE_RESPONSE_CC':
			ret = self.process_challenge_response_cc(message)

		# O cliente envia um pedido de autenticação do server
		elif mtype == 'SERVER_AUTH_REQ':
			ret = self.server_auth(message)
		# No caso de receber um error(nao conseguir autenticar-se pex.)
		elif mtype == 'ERROR':
			ret = False
		# OPEN file
		elif mtype == "OPEN":
			ret = self.process_open(message)
		# Data from the file
		elif mtype == "DATA":
			ret = self.process_data(message)
			# self.data_received(ret)
		# Close the conn
		elif mtype == "CLOSE":
			ret = self.process_close(message)
		else:
			logger.warning("Invalid message type: {}".format(message["type"]))
			ret = False

		if not ret:
			try:
				self._send({"type": "ERROR", "message": "See server"})
			except:
				pass  # Silently ignore

			logger.info("Closing transport")
			if self.file is not None:
				self.file.close()
				self.file = None

			self.state = STATE_CLOSE
			self.transport.close()

	# Received the "cifra, modo, sintese" from client
	def agreement(self, message: str):  # -> bool:
		self.state = STATE_NEGOTIATING
		if message['algoritmo'] not in self.protocols['cifras']:
			logger.info('Algoritmo not defined on Server')
			return False
		self.algoritmo = message["algoritmo"]  # Cifra a usar
		if message['modo'] not in self.protocols['modos']:
			logger.info('Modo not defined on Server')
			return False
		self.modo = message["modo"]  # Modo de cifra a usar
		if message['sintese'] not in self.protocols['sinteses']:
			logger.info('Sintese not defined on Server')
			return False
		self.sintese = message["sintese"]  # Função de cifra a usar
		self.iv = base64.b64decode(message['iv'])
		logger.info(
			f'algoritmo: {self.algoritmo}, modo: {self.modo}, sintese: {self.sintese}, iv:{self.iv}')
		# Envia ok, registei em que patamar estamos
		message = {'type': 'AGREEMENT_OK'}
		self._send(message)
		return True

	# Received key from the client
	def keys_exchange(self, message: str):  # -> bool:
		p = message['p']
		g = message['g']	
		pn = dh.DHParameterNumbers(p, g)
		parameters = pn.parameters(default_backend())
		
		# Calcular a privada
		self.sv_priv_key = parameters.generate_private_key()
		# Calcular a pública
		self.sv_pub_key = self.sv_priv_key.public_key()
		cli_pub_key_bytes = base64.b64decode(message['cli_pub_key'])
		
		cli_pub_key = serialization.load_der_public_key(cli_pub_key_bytes, backend=default_backend())

		shared_key = self.sv_priv_key.exchange(cli_pub_key)

		# Perform key derivation.
		self.key = HKDF(
			algorithm=hashes.SHA256(),
			length=16,
			salt=None,
			info=b'handshake data',
			backend=default_backend()
		).derive(shared_key)

		sv_pub_key_bites = self.sv_pub_key.public_bytes(
			serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
		)
		message = {'type': 'PUBLIC_SV_KEY',
					'sv_pub_key': base64.b64encode(sv_pub_key_bites).decode('utf-8'),
					}
		self._send(message)
		self.state = STATE_CONNECT
		return True

	# Envia nonce e guarda oq recebeu da mensagem
	def send_challenge_cc(self, message: str):
		ca_cert_cli_cc_bytes = base64.b64decode(message['CA_cert'])

		self.ca_cert_cli_cc = x509.load_der_x509_certificate(ca_cert_cli_cc_bytes, backend=default_backend())
		flag, chain = self.CCModule.issuers(self.ca_cert_cli_cc)
		retval = self.CCModule.verify(chain)
		if retval:
			logger.info('Sending challenge')
			self.challenge_nonce_cc = os.urandom(16)
			txt = str.encode(json.dumps({'type': 'CHALLENGE_CC', 'nonce': base64.b64encode(self.challenge_nonce_cc).decode('utf-8') }))
			payload, mac = self.encript(txt)
			msg = {
				'type': 'SECURE_MESSAGE',
				'payload': base64.b64encode(payload).decode('utf-8'),
				'HMAC': base64.b64encode(mac).decode('utf-8')
			}
			self._send(msg)
			return True
		else:
			logger.info('chain failed')
			self._send({'type': 'ERROR', "message": "See server"})
			# envia erro
			return False


	# Send challenge when requested by usr
	def send_challenge_password(self, message: str):
		rsa_cli_pub_key_bytes = base64.b64decode(message['RSA_CLI_PUB_KEY'])
		self.rsa_cli_pub_key = serialization.load_der_public_key(rsa_cli_pub_key_bytes, backend=default_backend())
		logger.info('Sending challenge')
		self.challenge_nonce_password = os.urandom(16)
		txt = str.encode(json.dumps({'type': 'CHALLENGE_PASSWORD', 'nonce': base64.b64encode(self.challenge_nonce_password).decode('utf-8') }))
		payload, mac = self.encript(txt)
		msg = {
			'type': 'SECURE_MESSAGE',
			'payload': base64.b64encode(payload).decode('utf-8'),
			'HMAC': base64.b64encode(mac).decode('utf-8')
		}
		self._send(msg)
		return True

	def process_challenge_response_cc(self, message: str):
		reply_nonce_cc = base64.b64decode(message['nonce'])
		# Recebe as coisas do servidor e vai ver se esta tudo como manda a lei
		if self.ca_cert_cli_cc.public_key().verify(reply_nonce_cc, self.challenge_nonce_cc, pdr.PKCS1v15(), hashes.SHA1()) == None:
			self._send({'type': 'AUTHENTICATION_OK'})
			logger.info('user authenticated')
			# envia um OK
			return True
		else:
			logger.info('user authentication failed')
			self._send({'type': 'ERROR', "message": "See server"})
			# envia erro
			return False

	# Check if the username password combination are valid
	def process_challenge_response_password(self, message: str):
		usr = message['username']
		password = base64.b64decode(message['password'])
		# Se o username nem contar nos usrs registados
		if usr not in self.users.keys(): 
			logger.info('User not registed')
			self._send({'type': 'ERROR', "message": "User not registed"})
			return False
		# Se o user nao esta autorizado a ler
		if self.users.get(usr)[1] != 'Y':
			logger.info('User not authorized to check content!')
			self._send({'type': 'ERROR', "message": "User not authorized"})
			return False
		if self.users.get(usr)[2] != message['question']:
			logger.info('User authentication!')
			self._send({'type': 'ERROR', "message": "User not authorized"})
			return False
		# O username conta nos registos, checka se a password esta correta
		else:
			# Vai buscar a password da "base de dados", adiciona o nonce e assina c a public key rsa do cli
			# e confirma se é igual	ao valor q recebeu, se nao for a pwd ta mal
			pwd = self.users.get(usr)[0].encode() + self.challenge_nonce_password
			hasher = hashes.Hash(hashes.SHA256(), default_backend())
			hasher.update(pwd)
			digest = hasher.finalize()
			try:
				self.rsa_cli_pub_key.verify(password, digest,
						pdr.PSS(mgf=pdr.MGF1(hashes.SHA256()), salt_length=pdr.PSS.MAX_LENGTH),
						utils.Prehashed(hashes.SHA256()))
				logger.info('user authenticated')
				self._send({'type': 'AUTHENTICATION_OK'})
				# envia um OK
				return True
			except:
				logger.info('user authentication failed')
				self._send({'type': 'ERROR', "message": "Authentication failed"})
				# envia erro
				return False


	def server_auth(self, message: str):
		self.server_auth_nonce = base64.b64decode(message['nonce'])
		# ? Carrega a private key do server
		with open("./keys/Server.pem", "rb") as key_file:
			self.server_cert_priv_key = serialization.load_pem_private_key(
			    key_file.read(), password=None, backend=default_backend())
		# ? Gera a publica e converte-a para bytes para a poder enviar
		self.server_cert_pub_key = self.server_cert_priv_key.public_key()
		
		# ? Assinar nonce c a private_key do server cert
		hasher = hashes.Hash(hashes.SHA256(), default_backend())
		hasher.update(self.server_auth_nonce)
		digest = hasher.finalize()
		signed_nonce = self.server_cert_priv_key.sign(digest, 
						pdr.PSS(mgf=pdr.MGF1(hashes.SHA256()), salt_length=pdr.PSS.MAX_LENGTH),
						utils.Prehashed(hashes.SHA256()))

		# ? Carrega cert do servidor
		with open("certs/CA_Certs/Server.crt", "rb") as server_certs:
			self.server_cert = x509.load_pem_x509_certificate(server_certs.read(), default_backend())
		server_cert_bytes = self.server_cert.public_bytes(serialization.Encoding.DER)

		# ENVIA: Nonce assinado, server cert, root cert, chave publica do certificado
		txt = str.encode(json.dumps({'type': 'SERVER_AUTH_REPLY', 
									'nonce': base64.b64encode(signed_nonce).decode('utf-8'),
									'server_cert': base64.b64encode(server_cert_bytes).decode('utf-8'),}))
		payload, mac = self.encript(txt)
		msg = {
			'type': 'SECURE_MESSAGE',
			'payload': base64.b64encode(payload).decode('utf-8'),
			'HMAC': base64.b64encode(mac).decode('utf-8')
		}
		self._send(msg)
		return True

	def encript(self, txt):
		cipher = None   # self.chiper
		block_size = 0
		# Algoritmo
		if self.algoritmo == 'AES':    # self.alg
			alg = algorithms.AES(self.key)
			block_size = alg.block_size
		elif self.algoritmo == 'CAST5':
			alg = algorithms.CAST5(self.key)
			block_size = alg.block_size
		# Modo de encriptografar
		if self.modo == 'ECB':   #self.mod ==
			mod = modes.ECB()
		elif self.modo == 'CBC':
			mod = modes.CBC(self.iv)
		# Self.cipher
		cipher = Cipher(alg, mod, backend=default_backend())
		# Sintese
		if self.sintese == 'SHA-256': # Self.sintese
			sints = hashes.SHA256()
		elif self.sintese == 'MD5':
			sints = hashes.MD5()

		encryptor = cipher.encryptor()
		h = hmac.HMAC(self.key, sints, backend=default_backend())
		# Text
		msg = base64.b64encode(txt)
		padder = padding.PKCS7(block_size).padder()
		padded_data = padder.update(msg) + padder.finalize()
		ct = encryptor.update(padded_data) + encryptor.finalize() #pkcs7

		# HMAC
		h.update(ct)
		mac = h.finalize()
		return ct, mac

	def decript(self, ct, mac):
		cipher = None   # self.chiper
		block_size = 0
		# Algoritmo
		if self.algoritmo == 'AES':
			alg = algorithms.AES(self.key)
			block_size = alg.block_size
		elif self.algoritmo == 'CAST5':
			alg = algorithms.CAST5(self.key)
			block_size = alg.block_size
		# Modo de encriptografar
		if self.modo == 'ECB':  # self.mod ==
			mod = modes.ECB()
		elif self.modo == 'CBC':
			mod = modes.CBC(self.iv)
		# Self.cipher
		cipher = Cipher(alg, mod, backend=default_backend())
		# Sintese
		if self.sintese == 'SHA-256':  # Self.sintese
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
		d = base64.b64decode(data)
		return d

	def process_open(self, message: str):  # -> bool:
		"""
		Processes an OPEN message from the client
		This message should contain the filename

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
		logger.debug("Process Open: {}".format(message))

		if self.state != STATE_CONNECT:
			logger.warning("Invalid state. Discarding")
			return False

		if not "file_name" in message:
			logger.warning("No filename in Open")
			return False

		# Only chars and letters in the filename
		file_name = re.sub(r"[^\w\.]", "", message["file_name"])
		file_path = os.path.join(self.storage_dir, file_name)
		if not os.path.exists("files"):
			try:
				os.mkdir("files")
			except:
				logger.exception("Unable to create storage directory")
				return False

		try:
			self.file = open(file_path, "wb")
			logger.info("File open")
		except Exception:
			logger.exception("Unable to open file")
			return False

		# Se tudo correu bem vai devolver um OK ao cliente
		txt = str.encode(json.dumps({"type": "OK"}))
		payload, mac = self.encript(txt)
		msg = {
		'type': 'SECURE_MESSAGE',
		'payload': base64.b64encode(payload).decode('utf-8'),
		'HMAC': base64.b64encode(mac).decode()
		}
		self._send(msg)
		self.file_name = file_name
		self.file_path = file_path
		self.state = STATE_OPEN
		return True

	def process_data(self, message: str):  # -> bool:
		"""
		Processes a DATA message from the client
		This message should contain a chunk of the file
		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""

		logger.debug("Process Data: {}".format(message))
		if self.state == STATE_OPEN:
			self.state = STATE_DATA
			# First Packet

		elif self.state == STATE_DATA:
			# Next packets
			pass

		else:
			logger.warning("Invalid state. Discarding")
			return False

		try:
			data = message.get('data', None)
			if data is None:
				logger.debug("Invalid message. No data found")
				return False

			bdata = base64.b64decode(message['data'])
		except:
			logger.exception("Could not decode base64 content from message.data")
			return False

		try:
			self.file.write(bdata)
			self.file.flush()
		except:
			logger.exception("Could not write to file")
			return False

		return True

	def process_close(self, message: str):  # -> bool:
		"""
		Processes a CLOSE message from the client.
		This message will trigger the termination of this session

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
		logger.debug("Process Close: {}".format(message))

		self.transport.close()
		if self.file is not None:
			self.file.close()
			self.file = None

		self.state = STATE_CLOSE
		logger.info('======================================== WORK DONE, BYE! ========================================')
		exit()
		return True

	def _send(self, message: str) -> None:
		"""
		Effectively encodes and sends a message
		:param message:
		:return:
		"""
		logger.info("Send: {}".format(message))

		message_b = (json.dumps(message) + "\r\n").encode()
		self.transport.write(message_b)

def main():
	global storage_dir

	parser = argparse.ArgumentParser(description="Receives files from clients.")
	parser.add_argument(
		"-v",
		action="count",
		dest="verbose",
		help="Shows debug messages (default=False)",
		default=0,
	)
	parser.add_argument(
		"-p",
		type=int,
		nargs=1,
		dest="port",
		default=5000,
		help="TCP Port to use (default=5000)",
	)

	parser.add_argument(
		"-d",
		type=str,
		required=False,
		dest="storage_dir",
		default="files",
		help="Where to store files (default=./files)",
	)

	args = parser.parse_args()
	storage_dir = os.path.abspath(args.storage_dir)
	level = logging.DEBUG if args.verbose > 0 else logging.INFO
	port = args.port
	if port <= 0 or port > 65535:
		logger.error("Invalid port")
		return

	if port < 1024 and not os.geteuid() == 0:
		logger.error("Ports below 1024 require eUID=0 (root)")
		return

	coloredlogs.install(level)
	logger.setLevel(level)

	logger.info("Port: {} LogLevel: {} Storage: {}".format(
		port, level, storage_dir))
	tcp_server(ClientHandler, worker=2, port=port, reuse_port=True)


if __name__ == "__main__":
	main()
