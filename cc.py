import PyKCS11
import binascii
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import datetime
from cryptography.hazmat.primitives.asymmetric import padding
import requests
import os
from cryptography.x509.oid import NameOID, ExtensionOID


PKCS11_LIB = '/usr/local/lib/libpteidpkcs11.so'

backend = default_backend()


class CCModule:

    def __init__(self):
        lib = PKCS11_LIB
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load(lib)
        while True:
            slots = self.pkcs11.getSlotList()
            if slots:
                self.session = self.pkcs11.openSession(slots[0])
                break
            input("No smartcard detected!")
        self.session.getSessionInfo()
        self.certificate = self.certificateCC()
        self.private_key = None
        self.roots = {}
        self.user_roots = {}
        self.server_cert = {}
        self.crl = self.certificate.extensions.get_extension_for_class(x509.CRLDistributionPoints)

    def crl_verification(self):
        for value in self.crl.value:
            for full_name in value.full_name:
                request = requests.get(full_name.value)
                crl = x509.load_der_x509_crl(request.content,default_backend())
        if not crl:
            return True
        else: return False

    def privateKeyCC(self):
        self.private_key = self.session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY), (PyKCS11.CKA_LABEL,'CITIZEN AUTHENTICATION KEY')])[0]
        return self.private_key

    def signature(self, private_key, data):
        mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)
        return bytes(self.session.sign(
            private_key, data, mechanism))

    def certificates(self):
        certificates = []
        attribute_keys = [key for key in list(
            PyKCS11.CKA.keys()) if isinstance(key, int)]
        for obj in self.session.findObjects():
            attributes = self.session.getAttributeValue(obj, attribute_keys)
            attributes = dict(
                zip(map(PyKCS11.CKA.get, attribute_keys), attributes))
            if attributes['CKA_CERTIFICATE_TYPE'] != None:
                certificates.append(x509.load_der_x509_certificate(
                    bytes(attributes['CKA_VALUE']), backend))
        return certificates

    def certificateCC(self):
        return self.certificates()[0]

    def certificate_expired(self,cert):
        now = datetime.datetime.now()
        return cert.not_valid_before <= now <= cert.not_valid_after 

    def issuers(self, cert, chain=[]):
        chain.append(cert)
        issuer = cert.issuer
        subject = cert.subject

        self.get_roots_and_user_roots()

        if issuer == subject and subject in self.roots:
            return True, chain   
        if issuer in self.user_roots:
            return self.issuers(self.user_roots[issuer], chain), chain
        if issuer in self.roots:
            return self.issuers(self.roots[issuer], chain), chain


        print("Unable to create trust chain")
        return False, chain

    def issuers_sv(self,cert,chain=[]):
        chain.append(cert)

        issuer = cert.issuer.rfc4514_string()
        subject = cert.subject.rfc4514_string()

        if issuer == subject and subject in self.server_cert:
            print("Chain complete")
            return True, chain
    
        if issuer in self.server_cert:
            return self.get_issuers(self.server_cert[issuer], chain), chain

        print("Unable to create the Trust Chain")
        return False, chain

    # ? DONT KNOW
    def certificate_in_file(self, path):
        with open(path, 'rb') as cert_file:
            data = cert_file.read()

        try:
            cert = x509.load_pem_x509_certificate(data, default_backend())
        except Exception:
            try:
                cert = x509.load_der_x509_certificate(data, default_backend())
            except Exception:
                raise exception.SignatureVerificationError(
                    "Failed to load certificate: %s" % path
                )
        if self.certificate_expired(cert):
            return cert
        return None

    def get_roots_and_user_roots(self):
        #Roots
        directory = "/etc/ssl/certs"
        for entry in os.scandir(directory):
            if entry.is_file():
                try:
                    cert = self.certificate_in_file(directory + "/" + str(entry.name))
                    if cert != None:
                        subject = cert.subject
                    self.roots[subject] = cert
                except:
                    print("Error in load cert")

        # User Roots
        directory = "./pem"
        for entry in os.scandir(directory):
            try:
                cert = self.certificate_in_file(directory + "/" + str(entry.name))
                if cert != None:
                    subject = cert.subject
                self.user_roots[subject] = cert
            except Exception as e :
                print(e)
                print("Error in load cert")
    
    def get_Server_cert(self):
        certs = []
        directory = "./certs/CA_Certs"
        for entry in os.scandir(directory):
            print(entry)
            try:
                cert = self.certificate_in_file(directory + "/" + str(entry.name))
                if cert != None:
                    subject = cert.subject
                    self.server_cert[subject] = cert
            except Exception as e:
                print(e)
                print("Error in load cert")

    def verify_server(self,chain):
        # * purpose
        if not x509.oid.ExtendedKeyUsageOID.SERVER_AUTH in chain[0].extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value: 
            print("Not valid [Server purpose]")
            return False
        for i in range(len(chain)-1):
            if not chain[0].extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value.digital_signature:
                print("Not valid [CC purpose]")
                return False
    
                for i in range(1,len(chain)):
                    if not chain[i].extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value.key_cert_sign:
                        print("Not valid [CC purpose]")
                        return False
    
                for i in range(len(chain)-1):
                    # * common name
                    if chain[i].issuer.get_attributes_for_oid(NameOID.COMMON_NAME) != chain[i+1].subject.get_attributes_for_oid(NameOID.COMMON_NAME):
                        print("Not valid [common name]")
                        print(chain[i].issuer.get_attributes_for_oid(NameOID.COMMON_NAME))
                        print(chain[i+1].issuer.get_attributes_for_oid(NameOID.COMMON_NAME))
                        return False
    
                    # * signature
                    try:
                        chain[i+1].public_key().verify(  chain[i].signature,\
                                                            chain[i].tbs_certificate_bytes,\
                                                            padding.PKCS1v15(),\
                                                            chain[i].signature_hash_algorithm)
                    except Exception:
                        print("Not valid [signature]")
                        return False
    
                    if self.crl_verification():
                        print("Not Valid [crl]")
                        return False
    
    
                    # * dates
                    if i == 0:
                        if not self.certificate_expired(chain[i]):
                            return False
                    '''
                    date_sign = chain[i].not_valid_before.timestamp() 
                    if chain[i+1].not_valid_before.timestamp() > chain[i].not_valid_before.timestamp() \
                        or chain[i].not_valid_before.timestamp() > chain[i+1].not_valid_after.timestamp():
                        print("Not Valid [Dates]")
                        break
                    '''
    
            return True


    # a data do subject tem que estar entre o before e after ( quando foi assinado o certificado acima tmb era valido)
    def verify(self,chain):
        ## CC
        if not chain[0].extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value.digital_signature:
            print("Not valid [CC purpose]")
            return False

        for i in range(1,len(chain)):
            if not chain[i].extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value.key_cert_sign:
                print("Not valid [CC purpose]")
                return False

        for i in range(len(chain)-1):
            # * common name
            if chain[i].issuer.get_attributes_for_oid(NameOID.COMMON_NAME) != chain[i+1].subject.get_attributes_for_oid(NameOID.COMMON_NAME):
                print("Not valid [common name]")
                print(chain[i].issuer.get_attributes_for_oid(NameOID.COMMON_NAME))
                print(chain[i+1].issuer.get_attributes_for_oid(NameOID.COMMON_NAME))
                return False

            # * signature
            try:
                chain[i+1].public_key().verify(  chain[i].signature,\
                                                    chain[i].tbs_certificate_bytes,\
                                                    padding.PKCS1v15(),\
                                                    chain[i].signature_hash_algorithm)
            except Exception:
                print("Not valid [signature]")
                return False

            if self.crl_verification():
                print("Not Valid [crl]")
                return False


            # * dates
            if i == 0:
                if not self.certificate_expired(chain[i]):
                    return False
            '''
            date_sign = chain[i].not_valid_before.timestamp() 
            if chain[i+1].not_valid_before.timestamp() > chain[i].not_valid_before.timestamp() \
                or chain[i].not_valid_before.timestamp() > chain[i+1].not_valid_after.timestamp():
                print("Not Valid [Dates]")
                break
            '''

        return True
