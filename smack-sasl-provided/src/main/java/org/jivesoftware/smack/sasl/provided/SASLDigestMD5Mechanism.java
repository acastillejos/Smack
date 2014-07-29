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
import org.jivesoftware.smack.sasl.SASLMechanism;
import org.jivesoftware.smack.util.ByteUtils;
import org.jivesoftware.smack.util.StringUtils;

public class SASLDigestMD5Mechanism extends SASLMechanism {

    public static final String NAME = DIGESTMD5;

    private static final String INITAL_NONCE = "00000001";

    /**
     * The state of the this instance of SASL DIGEST-MD5 authentication.
     */
    private State state = State.INITIAL;

    @Override
    protected void authenticateInternal(CallbackHandler cbh) throws SmackException {
        throw new UnsupportedOperationException("CallbackHandler not (yet) supported");
    }

    @Override
    protected String getAuthenticationText() throws SmackException {
        // DIGEST-MD5 has no initial response, return null
        return null;
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public int getPriority() {
        return 210;
    }

    @Override
    public SASLDigestMD5Mechanism newInstance() {
        return new SASLDigestMD5Mechanism();
    }

    @Override
    protected byte[] evaluateChallenge(byte[] challenge) throws SmackException {
        byte[] response = null;
        switch(state) {
        case INITIAL:
            if (challenge.length == 0) {
                throw new SmackException("Initial challenge has zero length");
            }
            String[] challengeParts = (new String(challenge)).split(",");
            String nonce = null;
            for (String part : challengeParts) {
                String[] keyValue = part.split("=");
                assert(keyValue.length == 2);
                String key = keyValue[0];
                String value = keyValue[1];
                if ("nonce".equals(key)) {
                    if (nonce != null) {
                        throw new SmackException("Nonce value present multiple times");
                    }
                    nonce = value.replace("\"", "");
                } else if ("charset".equals(key)) {
                    if (!value.equals("utf-8")) {
                        System.err.println("Unsupported charset");
                    }
                }
                else if ("qop".equals(key)) {
                    if (!value.equals("auth")) {
                        System.err.println("Unsupported qop operation");
                    }
                }
            }
            if (nonce == null) {
                // RFC 2831 2.1.1 about nonce "This directive is required and MUST appear exactly
                // once; if not present, or if multiple instances are present, the client should
                // abort the authentication exchange."
                throw new SmackException("nonce value not present in initial challenge");
            }
            // RFC 2831 2.1.2.1 defines A1, A2, KD and response-value
            byte[] a1FirstPart = ByteUtils.md5(toBytes(authenticationId + ':' + serviceName + ':' + password));
            String cnonce = StringUtils.randomString(32);
            byte[] a1 = ByteUtils.concact(a1FirstPart, toBytes(':' + nonce + ':' + cnonce));
            String digestUri = "xmpp/" + serviceName;
            byte[] a2 = toBytes("AUTHENTICATE:" + digestUri);
            String hex_hashed_a1 = StringUtils.encodeHex(ByteUtils.md5(a1));
            String hex_hashed_a2 = StringUtils.encodeHex(ByteUtils.md5(a2));
            byte[] kd = ByteUtils.md5(toBytes(hex_hashed_a1 + ':' + nonce + ':' + INITAL_NONCE + ':' + cnonce + ":auth:" + hex_hashed_a2));
            String responseValue = StringUtils.encodeHex(kd);
            // @formatter:off
            // See RFC 2831 2.1.2 digest-response
            String saslString = "username=\"" + authenticationId + '"'
                               + ",realm=\"" + serviceName + '"'
                               + ",nonce=\"" + nonce + '"'
                               + ",cnonce=\"" + cnonce + '"'
                               + ",nc=" + INITAL_NONCE
                               + ",qop=auth"
                               + ",digest-uri=\"" + digestUri + '"'
                               + ",response=" + responseValue
                               + ",charset=utf-8";
            // @formatter:on
            response = toBytes(saslString);
            state = State.RESPONSE_SENT;
            break;
        case RESPONSE_SENT:
            // TODO Validate the server response. All we can do here is verifying that the server
            // knows the user's password, but thats better then nothing.
            state = State.VALID_SERVER_RESPONSE;
            break;
         default:
             throw new IllegalStateException();
        }
        return response;
    }

    private enum State {
        INITIAL,
        RESPONSE_SENT,
        VALID_SERVER_RESPONSE,
    }

    private static byte[] toBytes(String string) {
        return StringUtils.toBytes(string);
    }
}