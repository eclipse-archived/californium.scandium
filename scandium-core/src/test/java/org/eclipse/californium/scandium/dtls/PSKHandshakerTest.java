/*******************************************************************************
 * Copyright (c) 2014, 2015 Bosch Software Innovations GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Derived from "ServerHandshakerTest".
 * 
 * General comments:
 * The "ClientHello/HelloVerifyRequest" handshake is processed by the 
 * DTLSConnect.processClientHello() prior to hand over Messages to the
 * server handshaker. So we get the ServerHello direct (instead of the
 * HelloVerifyRequest).
 *
 * Contributors:
 *    Kai Hudalla (Bosch Software Innovations GmbH) - initial creation of "ServerHandshakerTest"
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove certificate tests
 *                                                    add PSK tests
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;

import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.util.Date;
import java.util.List;

import org.eclipse.californium.scandium.category.Small;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.StaticExtendedPskStore;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;
import org.eclipse.californium.scandium.util.DatagramWriter;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class PSKHandshakerTest {

	public static final String IDENTITY_FOR_SERVER = "client for server";
	public static final String IDENTITY_FOR_ANONYMOUS = "client for anonymous";

	static public class TestExtendedPskStore extends StaticExtendedPskStore {
		public TestExtendedPskStore(String identity, byte[] key) {
			super(null, identity, key);
		}

		@Override
		public String getIdentity(InetSocketAddress inetAddress, String identityHint) {
			if (null == identityHint || identityHint.isEmpty()) {
				return IDENTITY_FOR_ANONYMOUS;
			} else {
				return IDENTITY_FOR_SERVER;
			}
		}
	}

	ClientHandshaker clientHandshaker;
	ServerHandshaker serverHandshaker;
	DTLSSession clientSession;
	DTLSSession serverSession;
	InetSocketAddress clientEndpoint = InetSocketAddress.createUnresolved("localhost", 10000);
	InetSocketAddress serverEndpoint = InetSocketAddress.createUnresolved("localhost", 10001);
	byte[] sessionId = new byte[]{(byte) 0x0A, (byte) 0x0B, (byte) 0x0C, (byte) 0x0D, (byte) 0x0E, (byte) 0x0F};
	// ciphers supported by client: 0xC0A8 = TLS_PSK_WITH_AES_128_CCM_8
	byte[] supportedCiphers = new byte[]{ (byte) 0xC0, (byte) 0xA8, };
	byte[] random;
	byte[] clientHelloMsg;

	String identityHint = "server";
	String identity = "client";
	String distinguishedIdentity = "clientForServer";
	byte[] key = "secret".getBytes();

	@Before
	public void setup() throws Exception {
		serverSession = new DTLSSession(serverEndpoint, false);
		clientSession = new DTLSSession(clientEndpoint, true);

		// server
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(serverEndpoint);
		builder.setPskStore(new StaticPskStore(identity, key));
		builder.setSupportedCipherSuites(new CipherSuite[]{CipherSuite.TLS_PSK_WITH_AES_128_CCM_8});
		serverHandshaker = new ServerHandshaker(clientSession, null, builder.build());

		// client
		builder = new DtlsConnectorConfig.Builder(clientEndpoint);
		builder.setPskStore(new StaticPskStore(identity, key));
		builder.setSupportedCipherSuites(new CipherSuite[]{CipherSuite.TLS_PSK_WITH_AES_128_CCM_8});
		clientHandshaker = new ClientHandshaker(null, serverSession, null, builder.build());

		DatagramWriter writer = new DatagramWriter();
		// uint32 gmt_unix_time
		Date now = new Date();
		writer.writeLong(Math.round(now.getTime() / 1000), 32);
		// opaque random_bytes[28]
		for (int i = 0; i < 28; i++) {
			writer.write(i, 8);
		}
		random = writer.toByteArray();
	}

	public void setupServerExtendedPskStore(String identityHint) throws HandshakeException {
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(serverEndpoint);
		builder.setPskStore(new StaticExtendedPskStore(identityHint, identity, key));
		builder.setSupportedCipherSuites(new CipherSuite[]{CipherSuite.TLS_PSK_WITH_AES_128_CCM_8});
		serverHandshaker = new ServerHandshaker(clientSession, null, builder.build());
	}

	public void setupClientExtendedPskStore() throws HandshakeException {
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(clientEndpoint);
		builder.setPskStore(new TestExtendedPskStore(identity, key));
		builder.setSupportedCipherSuites(new CipherSuite[]{CipherSuite.TLS_PSK_WITH_AES_128_CCM_8});
		clientHandshaker = new ClientHandshaker(null, serverSession, null, builder.build());
	}

	@Test()
	public void testPresharedKeyHandshake() throws HandshakeException, GeneralSecurityException {
		// Test without using identity hint
		DTLSFlight clientFlight = clientHandshaker.getStartHandshakeMessage();

		assertThat(clientFlight, notNullValue());
		List<Record> messages = clientFlight.getMessages();
		assertThat(messages.size(), is(1));
		assertThat(messages.get(0).getFragment(), instanceOf(ClientHello.class));

		DTLSFlight serverFlight = processFlight(serverHandshaker, clientFlight);
		messages = serverFlight.getMessages();
		assertThat(messages.size(), is(2));
		assertThat(messages.get(0).getFragment(), instanceOf(ServerHello.class));
		assertThat(messages.get(1).getFragment(), instanceOf(ServerHelloDone.class));

		clientFlight = processFlight(clientHandshaker, serverFlight);
		messages = clientFlight.getMessages();
		assertThat(messages.size(), is(3));
		assertThat(messages.get(0).getFragment(), instanceOf(PSKClientKeyExchange.class));
		assertThat(messages.get(1).getFragment(), instanceOf(ChangeCipherSpecMessage.class));
		assertThat(messages.get(2).getFragment(), instanceOf(Finished.class));

		PSKClientKeyExchange clientKey = (PSKClientKeyExchange) messages.get(0).getFragment();
		assertThat(clientKey.getIdentity(), is(identity));
	}

	@Test()
	public void testPresharedKeyHandshakeWithIdentityHint() throws HandshakeException, GeneralSecurityException {
		// Test using identity hint

		setupServerExtendedPskStore(identityHint);
		setupClientExtendedPskStore();

		DTLSFlight clientFlight = clientHandshaker.getStartHandshakeMessage();
		assertThat(clientFlight, notNullValue());
		List<Record> messages = clientFlight.getMessages();
		assertThat(messages.size(), is(1));
		assertThat(messages.get(0).getFragment(), instanceOf(ClientHello.class));

		DTLSFlight serverFlight = processFlight(serverHandshaker, clientFlight);
		messages = serverFlight.getMessages();
		assertThat(messages.size(), is(3));
		assertThat(messages.get(0).getFragment(), instanceOf(ServerHello.class));
		assertThat(messages.get(1).getFragment(), instanceOf(PSKServerKeyExchange.class));
		assertThat(messages.get(2).getFragment(), instanceOf(ServerHelloDone.class));

		PSKServerKeyExchange serverKey = (PSKServerKeyExchange) messages.get(1).getFragment();
		assertThat(serverKey.getHint(), is(identityHint));

		clientFlight = processFlight(clientHandshaker, serverFlight);
		messages = clientFlight.getMessages();
		assertThat(messages.size(), is(3));
		assertThat(messages.get(0).getFragment(), instanceOf(PSKClientKeyExchange.class));
		assertThat(messages.get(1).getFragment(), instanceOf(ChangeCipherSpecMessage.class));
		assertThat(messages.get(2).getFragment(), instanceOf(Finished.class));

		PSKClientKeyExchange clientKey = (PSKClientKeyExchange) messages.get(0).getFragment();
		assertThat(clientKey.getIdentity(), is(IDENTITY_FOR_SERVER));
	}

	@Test()
	public void testPresharedKeyHandshakeWithEmptyIdentityHint() throws HandshakeException, GeneralSecurityException {
		// Test without using empty identity hint

		setupServerExtendedPskStore(null);
		setupClientExtendedPskStore();

		DTLSFlight clientFlight = clientHandshaker.getStartHandshakeMessage();
		assertThat(clientFlight, notNullValue());
		List<Record> messages = clientFlight.getMessages();
		assertThat(messages.size(), is(1));
		assertThat(messages.get(0).getFragment(), instanceOf(ClientHello.class));

		DTLSFlight serverFlight = processFlight(serverHandshaker, clientFlight);
		messages = serverFlight.getMessages();
		assertThat(messages.size(), is(2));
		assertThat(messages.get(0).getFragment(), instanceOf(ServerHello.class));
		assertThat(messages.get(1).getFragment(), instanceOf(ServerHelloDone.class));

		clientFlight = processFlight(clientHandshaker, serverFlight);
		messages = clientFlight.getMessages();
		assertThat(messages.size(), is(3));
		assertThat(messages.get(0).getFragment(), instanceOf(PSKClientKeyExchange.class));
		assertThat(messages.get(1).getFragment(), instanceOf(ChangeCipherSpecMessage.class));
		assertThat(messages.get(2).getFragment(), instanceOf(Finished.class));

		PSKClientKeyExchange clientKey = (PSKClientKeyExchange) messages.get(0).getFragment();
		assertThat(clientKey.getIdentity(), is(IDENTITY_FOR_ANONYMOUS));
	}

	@Test()
	public void testPresharedKeyHandshakeWithIdentityHintAndAgnosticClient() throws HandshakeException, GeneralSecurityException {
		// Test using identity hint only on server side. Client side ignores the hint
		setupServerExtendedPskStore(identityHint);

		DTLSFlight clientFlight = clientHandshaker.getStartHandshakeMessage();
		assertThat(clientFlight, notNullValue());
		List<Record> messages = clientFlight.getMessages();
		assertThat(messages.size(), is(1));
		assertThat(messages.get(0).getFragment(), instanceOf(ClientHello.class));

		DTLSFlight serverFlight = processFlight(serverHandshaker, clientFlight);
		messages = serverFlight.getMessages();
		assertThat(messages.size(), is(3));
		assertThat(messages.get(0).getFragment(), instanceOf(ServerHello.class));
		assertThat(messages.get(1).getFragment(), instanceOf(PSKServerKeyExchange.class));
		assertThat(messages.get(2).getFragment(), instanceOf(ServerHelloDone.class));

		PSKServerKeyExchange serverKey = (PSKServerKeyExchange) messages.get(1).getFragment();
		assertThat(serverKey.getHint(), is(identityHint));

		clientFlight = processFlight(clientHandshaker, serverFlight);
		messages = clientFlight.getMessages();
		assertThat(messages.size(), is(3));
		assertThat(messages.get(0).getFragment(), instanceOf(PSKClientKeyExchange.class));
		assertThat(messages.get(1).getFragment(), instanceOf(ChangeCipherSpecMessage.class));
		assertThat(messages.get(2).getFragment(), instanceOf(Finished.class));

		PSKClientKeyExchange clientKey = (PSKClientKeyExchange) messages.get(0).getFragment();
		assertThat(clientKey.getIdentity(), is(identity));
	}

	@Test()
	public void testPresharedKeyHandshakeWithAgnosticServer() throws HandshakeException, GeneralSecurityException {
		// Test without using identity hint but client would be able to process it.
		
		setupClientExtendedPskStore();
		
		DTLSFlight clientFlight = clientHandshaker.getStartHandshakeMessage();
		assertThat(clientFlight, notNullValue());
		List<Record> messages = clientFlight.getMessages();
		assertThat(messages.size(), is(1));
		assertThat(messages.get(0).getFragment(), instanceOf(ClientHello.class));

		DTLSFlight serverFlight = processFlight(serverHandshaker, clientFlight);
		messages = serverFlight.getMessages();
		assertThat(messages.size(), is(2));
		assertThat(messages.get(0).getFragment(), instanceOf(ServerHello.class));
		assertThat(messages.get(1).getFragment(), instanceOf(ServerHelloDone.class));

		clientFlight = processFlight(clientHandshaker, serverFlight);
		messages = clientFlight.getMessages();
		assertThat(messages.size(), is(3));
		assertThat(messages.get(0).getFragment(), instanceOf(PSKClientKeyExchange.class));
		assertThat(messages.get(1).getFragment(), instanceOf(ChangeCipherSpecMessage.class));
		assertThat(messages.get(2).getFragment(), instanceOf(Finished.class));

		PSKClientKeyExchange clientKey = (PSKClientKeyExchange) messages.get(0).getFragment();
		assertThat(clientKey.getIdentity(), is(IDENTITY_FOR_ANONYMOUS));
	}

	private DTLSFlight processFlight(Handshaker handshaker, DTLSFlight flight) throws HandshakeException, GeneralSecurityException {
		DTLSFlight result = new DTLSFlight(flight.getSession());
		for (Record record: flight.getMessages()) {
			// setFragment to null triggers the getFragment() to (re-)read the fragment from the bytes
			// Otherwise HandshakeMessage.getRawMessage() would return null and breaks the test with 
			//		java.lang.NullPointerException
			//		at java.security.MessageDigest.update(MessageDigest.java:335)
			//		at org.eclipse.californium.scandium.dtls.ServerHandshaker.receivedClientHello(ServerHandshaker.java:486)
			record.setFragment(null);
			DTLSFlight recvFlight = handshaker.processMessage(record);
			if (null != recvFlight) {
				result.addMessage(recvFlight.getMessages());
			}
		}
		return result;
	}
}
