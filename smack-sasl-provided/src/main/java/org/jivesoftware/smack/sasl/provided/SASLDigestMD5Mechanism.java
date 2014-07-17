/**
 *
 * Copyright 2014 Florian Schmaus
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jivesoftware.smack.sasl.provided;

import javax.security.auth.callback.CallbackHandler;

import org.jivesoftware.smack.SmackException;
import org.jivesoftware.smack.XMPPConnection;
import org.jivesoftware.smack.sasl.SASLMechanism;

public class SASLDigestMD5Mechanism extends SASLMechanism {

	@Override
	protected void authenticateInternal(XMPPConnection connection,
			String username, String host, String serviceName, String password)
			throws SmackException {
		// TODO Auto-generated method stub

	}

	@Override
	protected void authenticateInternal(XMPPConnection connection, String host,
			CallbackHandler cbh) throws SmackException {
		// TODO Auto-generated method stub

	}

	@Override
	protected String getAuthenticationText() throws SmackException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getName() {
		return "DIGEST-MD5";
	}

	@Override
	public int getPriority() {
		return 210;
	}

	@Override
	public SASLDigestMD5Mechanism newInstance() {
		return new SASLDigestMD5Mechanism();
	}

}
