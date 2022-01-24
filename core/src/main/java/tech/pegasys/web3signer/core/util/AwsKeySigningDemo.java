package tech.pegasys.web3signer.core.util;

import org.apache.tuweni.bytes.Bytes;
import tech.pegasys.web3signer.core.AwsKmsSigner;
import tech.pegasys.web3signer.core.AwsSecretsManagerSigner;
import tech.pegasys.web3signer.core.signing.ArtifactSignature;

import java.nio.charset.StandardCharsets;

public class AwsKeySigningDemo {

  public static void KmsDemo(String keyId, Bytes data) {
    AwsKmsSigner awsKmsSigner = new AwsKmsSigner(keyId);
    System.out.println(awsKmsSigner.getIdentifier());

    ArtifactSignature signature = awsKmsSigner.sign(data);
    System.out.println(signature.toString());
  }

  public static void SecretsManagerDemo(String secretName, Bytes data){
    AwsSecretsManagerSigner awsSecretsManagerSigner = new AwsSecretsManagerSigner(secretName);
    System.out.println(awsSecretsManagerSigner.getIdentifier());

    ArtifactSignature signature = awsSecretsManagerSigner.sign(data);
    System.out.println(signature.toString());
  }

  public static void main(String[] args){

    String kmsKeyId = "66496115-ce45-4cf1-8f4e-6aa0849d6e3f";
    String secretsManagerSecretName = "arn:aws:secretsmanager:us-east-2:504983140689:secret:web3signer-demo-31SzWP";
    Bytes data = Bytes.wrap("hello, world".getBytes(StandardCharsets.UTF_8));

    System.out.println("KMS demo:");
    KmsDemo(kmsKeyId, data);

    System.out.println("Secrets manager demo:");
    SecretsManagerDemo(secretsManagerSecretName, data);

  }

}
