package tech.pegasys.web3signer.core;

import org.apache.tuweni.bytes.Bytes;
import tech.pegasys.web3signer.core.signing.ArtifactSignature;
import tech.pegasys.web3signer.core.signing.ArtifactSigner;
import tech.pegasys.web3signer.core.signing.SecpArtifactSignature;

public class AwsKmsSigner implements ArtifactSigner {

    private AwsKmsKey awsKmsKey;
    private String publicKey;

    public AwsKmsSigner(String keyId) {
        this.awsKmsKey = new AwsKmsKey(keyId);
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
}