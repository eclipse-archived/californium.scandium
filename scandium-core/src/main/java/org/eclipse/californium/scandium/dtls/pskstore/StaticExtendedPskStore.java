package org.eclipse.californium.scandium.dtls.pskstore;

import java.net.InetSocketAddress;

/**
 * An simple in-memory pre-shared-key storage.
 * Used when we always use the same identity/Key for all peers
 * we will connect to. 
 * 
 * To be used only for testing and evaluation. 
 * You are supposed to store your key in a secure way: 
 * keeping them in-memory is not a good idea.
 */
public class StaticExtendedPskStore implements ExtendedPskStore{
	
	private final byte[] key;
	private final String identity;
	private final String identityHint;

	public StaticExtendedPskStore(String identityHint, String identity, byte[] key) {
		this.identityHint = identityHint;
		this.identity = identity;
		this.key = key;
	}
	
	@Override
	public String getIdentity(InetSocketAddress inetAddress) {
		return identity;
	}
	
	@Override
	public byte[] getKey(String identity) {
		return key;
	}

	@Override
	public String getIdentityHint() {
		return identityHint;
	}

	@Override
	public String getIdentity(InetSocketAddress inetAddress, String identityHint) {
		return identity;
	}
}
