package tech.pegasys.web3signer.core;

import org.apache.tuweni.bytes.Bytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import tech.pegasys.web3signer.core.signing.ArtifactSignature;

import java.nio.charset.StandardCharsets;

public class AwsKeySigningDemo {

  public static void KmsDemo(KmsClient kmsClient, String keyId, Bytes data) {
    AwsKmsSigner awsKmsSigner = new AwsKmsSigner(kmsClient, keyId);
    System.out.println("Public key: " + awsKmsSigner.getIdentifier());

    ArtifactSignature signature = awsKmsSigner.sign(data);
    System.out.println("Signature: " + signature.toString());
    //awsKmsSigner.verifyMessage(signature, data);

    awsKmsSigner.close();
  }

  public static void SecretsManagerDemo(SecretsManagerClient secretsManagerClient, String secretName, Bytes data, String password){
    AwsSecretsManagerSigner awsSecretsManagerSigner = new AwsSecretsManagerSigner(secretsManagerClient, secretName, password);
    System.out.println("Public key: " + awsSecretsManagerSigner.getIdentifier());

    ArtifactSignature signature = awsSecretsManagerSigner.sign(data);
    System.out.println("Signature: " + signature.toString());
  }

  public static void main(String[] args){
    Bytes data = Bytes.wrap("hello, world".getBytes(StandardCharsets.UTF_8));

//    String kmsKeyId = "66496115-ce45-4cf1-8f4e-6aa0849d6e3f";
//    KmsClient kmsClient = AwsKmsKey.createKmsClient();
//    System.out.println("KMS demo:");
//    KmsDemo(kmsClient, kmsKeyId, data);

    String secretsManagerSecretName = "arn:aws:secretsmanager:us-east-2:504983140689:secret:web3signer-demo-31SzWP";
    String keystorePassword = "test";
    SecretsManagerClient secretsManagerClient = AwsSecretsManagerKey.createSecretsManagerClient();
    System.out.println("Secrets manager demo:");
    SecretsManagerDemo(secretsManagerClient, secretsManagerSecretName, data, keystorePassword);
  }

}
