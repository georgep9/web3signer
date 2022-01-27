package tech.pegasys.web3signer.core;

import org.apache.tuweni.bytes.Bytes;
import software.amazon.awssdk.services.kms.KmsClient;
import tech.pegasys.web3signer.core.signing.ArtifactSignature;
import tech.pegasys.web3signer.core.signing.ArtifactSigner;
import tech.pegasys.web3signer.core.signing.SecpArtifactSignature;

import java.nio.charset.StandardCharsets;

public class AwsKmsSigner implements ArtifactSigner {

    private AwsKmsKey awsKmsKey;
    private String publicKey;

    public AwsKmsSigner(KmsClient kmsClient, String keyId) {
        this.awsKmsKey = new AwsKmsKey(kmsClient, keyId);
        this.publicKey = this.awsKmsKey.publicKey();
    }

    @Override
    public String getIdentifier() {
      return this.publicKey;
    }

    @Override
    public ArtifactSignature sign(Bytes message) {
      byte[] signature = this.awsKmsKey.signData(message.toArray());
      return SecpArtifactSignature.fromBytes(Bytes.wrap(signature));
    }

    public boolean verifyMessage(ArtifactSignature signature, Bytes message) {
      boolean isValid = this.awsKmsKey.verifyData(signature.toString().getBytes(StandardCharsets.UTF_8), message.toArray());
      if (isValid){
        System.out.println("Successfully signed and verified.");
        return true;
      }
      else {
        return false;
      }
    }

    public void close() { this.awsKmsKey.close(); }
}
