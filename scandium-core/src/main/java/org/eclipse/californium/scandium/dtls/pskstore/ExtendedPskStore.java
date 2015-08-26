/*******************************************************************************
 * Copyright (c) 2015 Bosch Software Innovations GmbH and others.
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
 * Contributors:
 *    Achim Kraus (Bosch Software Innovations GmbH) - add/enable optional server 
 *                                                    identity hint support.
 *
 ******************************************************************************/

package org.eclipse.californium.scandium.dtls.pskstore;

import java.net.InetSocketAddress;

/**
 * A extended storage for pre-shared-key identity and server identity hint.
 * If pskStore of {@link org.eclipse.californium.scandium.config.DtlsConnectorConfig} 
 * implements this interface and returns a none null not empty identity hint, the 
 * {@link org.eclipse.californium.scandium.dtls.ServerHandshaker} will include the
 * returned identity hint in the {@link org.eclipse.californium.scandium.dtls.PSKServerKeyExchange}.
 */
public interface ExtendedPskStore extends PskStore {

	/**
	 * Get identity hint. Used from server to indicates the servers identity in the handshakes .
	 * 
	 * @return The identity hint of server or <code>null</code> if not provided
	*/
	String getIdentityHint();
	
	/**
	 * Get Identity for a peer address, this is used 
	 * when we need to initiate the connection. 
	 * In this case we need to know the identity to use for the given peer
	 * @param inetAddress address of the peer we want to connect to
	 * @param identityHint identity hint provided by server
	 * @return The identity of peer or <code>null</code> if not found
	 */
	String getIdentity(InetSocketAddress inetAddress, String identityHint);

}
