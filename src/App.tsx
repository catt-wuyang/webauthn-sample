import axios from "axios";
import "./App.css";

const login_user_id = "78cbc993-4512-480f-b29e-d495d3f24329";
const base_url = "http://localhost:4001";

function App() {
  const getRegistrationChallenge = async (userId: string) => {
    const response = await axios.post(
      `${base_url}/generate-registration-challenge`,
      {
        user_id: userId,
      }
    );
    const result = response.data;
    return result;
  };

  const fetchRegistration = async (credential: any) => {
    const response = await axios.post(`${base_url}/register`, credential);
    const result = response.data;
    return result;
  };

  const getAuthenticationChallenge = async (userId: string) => {
    const response = await axios.post(
      `${base_url}/generate-authentication-challenge`,
      {
        user_id: userId,
      }
    );
    const result = response.data;
    return result;
  };

  const verifyWebauthn = async (credential: any) => {
    const response = await axios.post(
      `${base_url}/verify-webauthn`,
      credential
    );
    const result = response.data;
    return result;
  };

  // 服务端返回的 challenge, user.id 都是 base64 格式，
  // 但 navigator.credentials.create 要求是 ArrayBuffer 或 ArrayBufferView 格式的
  const base64UrlToArrayBuffer = (base64Url: string) => {
    const base64 =
      base64Url.replace(/-/g, "+").replace(/_/g, "/") +
      "==".slice((2 - base64Url.length * 3) & 3);
    const raw = atob(base64);
    const bytes = new Uint8Array(new ArrayBuffer(raw.length));
    for (let i = 0; i < raw.length; ++i) {
      bytes[i] = raw.charCodeAt(i);
    }
    return bytes.buffer;
  };

  const arrayBufferToBase64Url = (arrayBuffer: any) => {
    const byteArray = new Uint8Array(arrayBuffer);
    let binaryString = "";
    for (let i = 0; i < byteArray.byteLength; i++) {
      binaryString += String.fromCharCode(byteArray[i]);
    }
    const base64 = btoa(binaryString);
    const base64Url = base64
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    return base64Url;
  };

  const handleRegistation = async () => {
    try {
      if (!navigator.credentials) {
        throw new Error(
          "Web Authentication API not support on current browser."
        );
      }

      const options = await getRegistrationChallenge(login_user_id);
      console.log(options);

      if (!options) {
        return false;
      }

      options.challenge = base64UrlToArrayBuffer(options.challenge);
      options.user.id = base64UrlToArrayBuffer(options.user.id);

      const credential = await navigator.credentials.create({
        publicKey: options,
      });

      console.log("credential", credential);
      if (!credential) {
        return false;
      }

      // register
      if (credential instanceof PublicKeyCredential) {
        if (credential.response instanceof AuthenticatorAttestationResponse) {
          console.log(credential.id);
          console.log(
            arrayBufferToBase64Url(credential.response.getPublicKey())
          );
          const credentialJson = {
            credential: {
              id: credential?.id,
              publicKey: arrayBufferToBase64Url(
                credential.response.getPublicKey()
              ),
              algorithm: credential.response.getPublicKeyAlgorithm(),
              type: credential?.type,
            },
            authenticatorData: arrayBufferToBase64Url(
              credential.response.getAuthenticatorData()
            ),
            attestationData: arrayBufferToBase64Url(
              credential.response.attestationObject
            ),
            clientData: arrayBufferToBase64Url(
              credential.response.clientDataJSON
            ),
          };

          console.log(credentialJson);
          const result = await fetchRegistration(credentialJson);
          if (result && result.code === 200) {
            alert(result.message);
          }
        }
      }
    } catch (error) {
      console.error("Failed to verify identity", error);
    }
  };

  const handleAuthentication = async () => {
    try {
      if (!navigator.credentials) {
        throw new Error(
          "Web Authentication API not support on current browser."
        );
      }

      let options = await getAuthenticationChallenge(login_user_id);
      console.log(options);

      if (!options) {
        return false;
      }

      options = {
        challenge: base64UrlToArrayBuffer(options.challenge),
        rpId: "webauthn demo",
        allowCredentials: options.allowCredentials,
        userVerification: "required",
        timeout: 60000,
      };

      let auth = await navigator.credentials.get({
        publicKey: options,
      });

      console.log(auth);

      // options.challenge = base64UrlToArrayBuffer(options.challenge);
      // options.user.id = base64UrlToArrayBuffer(options.user.id);

      // console.log("credential", credential);
    } catch (error) {
      console.error("Failed to verify identity", error);
    }
  };

  return (
    <>
      <h1>WebAuthn Demo</h1>
      <input
        type="text"
        disabled
        value={"78cbc993-4512-480f-b29e-d495d3f24329"}
      />
      <div className="button-wrap">
        <button onClick={handleRegistation}>Register</button>
        <button onClick={handleAuthentication}>Authenticate</button>
      </div>
    </>
  );
}

export default App;
