package tech.pegasys.web3signer.core;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import tech.pegasys.teku.bls.BLS;
import tech.pegasys.teku.bls.BLSSecretKey;
import tech.pegasys.web3signer.core.signing.ArtifactSignature;
import tech.pegasys.web3signer.core.signing.ArtifactSigner;
import tech.pegasys.web3signer.core.signing.BlsArtifactSignature;

public class AwsSecretsManagerSigner implements ArtifactSigner {

  private String publicKey;
  private byte[] privateKey;

  public AwsSecretsManagerSigner(String secretName){
    AwsSecretsManagerKey awsSecretsManagerKey = new AwsSecretsManagerKey(secretName);
    this.publicKey = awsSecretsManagerKey.getPublicKey();
    this.privateKey = awsSecretsManagerKey.getPrivateKey();
    awsSecretsManagerKey.close();
  }

  @Override
  public String getIdentifier() {
    return this.publicKey;
  }

  @Override
  public ArtifactSignature sign(Bytes message) {
    BLSSecretKey blsSecretKey = BLSSecretKey.fromBytes(Bytes32.wrap(this.privateKey));
    return new BlsArtifactSignature(BLS.sign(blsSecretKey, message));
  }
}
