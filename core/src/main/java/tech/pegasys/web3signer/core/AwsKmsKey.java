package tech.pegasys.web3signer.core;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.KeyMetadata;
import software.amazon.awssdk.services.kms.model.DescribeKeyRequest;
import software.amazon.awssdk.services.kms.model.DescribeKeyResponse;
import software.amazon.awssdk.services.kms.model.KmsException;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.VerifyRequest;
import software.amazon.awssdk.services.kms.model.VerifyResponse;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;


import software.amazon.awssdk.regions.Region;

import java.nio.charset.StandardCharsets;

public class AwsKmsKey {

    private KmsClient kmsClient;
    private KeyMetadata keyMetadata;
    private String publicKey;

    public static KmsClient createKmsClient(){
        Region region = Region.US_EAST_2;
        KmsClient kmsClient = KmsClient.builder()
                .region(region)
                .build();
        return kmsClient;
    }

    public static KeyMetadata fetchKmsKeyMetadata(KmsClient kmsClient, String keyId){
        try {
            DescribeKeyRequest keyRequest = DescribeKeyRequest.builder()
                    .keyId(keyId)
                    .build();
            DescribeKeyResponse response = kmsClient.describeKey(keyRequest);
            return response.keyMetadata();
        } catch (KmsException e) {
            System.err.println(e.getMessage());
            System.exit(1);
            return null;
        }
    }

    public void describeKey() { describeKey(this.keyMetadata); }

    public static void describeKey(KeyMetadata keyMetadata){
        System.out.println("The key description is "+keyMetadata.description());
        System.out.println("The key ARN is "+keyMetadata.arn());
        System.out.println("The key signing algorithm is "+keyMetadata.signingAlgorithmsAsStrings());
        System.out.println("The key spec is "+keyMetadata.customerMasterKeySpecAsString());
    }

    public byte[] signData(byte[] data){
        return signData(this.kmsClient, this.keyMetadata, data);
    }

    public static byte[] signData(KmsClient kmsClient, KeyMetadata keyMetadata, byte[] data){
        try {
            SdkBytes messageBytes = SdkBytes.fromByteArray(data);

            SignRequest signRequest = SignRequest.builder()
                    .keyId(keyMetadata.keyId())
                    .message(messageBytes)
                    .signingAlgorithm(keyMetadata.signingAlgorithms().get(0))
                    .build();

            SignResponse signResponse = kmsClient.sign(signRequest);
            byte[] signature = signResponse.signature().asByteArray();
            return signature;

        } catch (KmsException e) {
            System.err.println(e.getMessage());
            System.exit(1);
            return null;
        }
    }

    public boolean verifyData(byte[] signature, byte[] data){
        return verifyData(this.kmsClient, this.keyMetadata, signature, data);
    }

    public static boolean verifyData(KmsClient kmsClient, KeyMetadata keyMetadata, byte[] signature, byte[] data){
        try {
            SdkBytes signatureBytes = SdkBytes.fromByteArray(signature);
            SdkBytes messageBytes = SdkBytes.fromByteArray(data);

            VerifyRequest verifyRequest = VerifyRequest.builder()
                    .keyId(keyMetadata.keyId())
                    .signature(signatureBytes)
                    .message(messageBytes)
                    .signingAlgorithm(keyMetadata.signingAlgorithms().get(0))
                    .build();

            VerifyResponse verifyResponse = kmsClient.verify(verifyRequest);
            return verifyResponse.signatureValid();
        } catch (KmsException e) {
            System.err.println(e.getMessage());
            System.exit(1);
            return false;
        }
    }

    public String getPublicKey(){
        return getPublicKey(this.kmsClient, this.keyMetadata);
    }

    public static String getPublicKey(KmsClient kmsClient, KeyMetadata keyMetadata){
        try {
            GetPublicKeyRequest getPublicKeyRequest = GetPublicKeyRequest.builder()
                    .keyId(keyMetadata.keyId())
                    .build();

            GetPublicKeyResponse getPublicKeyResponse = kmsClient.getPublicKey(getPublicKeyRequest);
            return getPublicKeyResponse.publicKey().toString();
        } catch (KmsException e) {
            System.err.println(e.getMessage());
            System.exit(1);
            return null;
        }
    };

    public String publicKey() { return this.publicKey; }

    public void close() { this.kmsClient.close(); }

    public AwsKmsKey(String keyId){
        this.kmsClient = createKmsClient();
        this.keyMetadata = fetchKmsKeyMetadata(this.kmsClient, keyId);
        this.publicKey = getPublicKey(this.kmsClient, this.keyMetadata);
    }

    public static void main(String[] args){
        AwsKmsKey awsKmsKey = new AwsKmsKey("66496115-ce45-4cf1-8f4e-6aa0849d6e3f");
        awsKmsKey.describeKey();
        byte[] data = "hello, world".getBytes(StandardCharsets.UTF_8);
        byte[] signature = awsKmsKey.signData(data);
        boolean isValid = awsKmsKey.verifyData(signature, data);
        if (isValid){
            System.out.println("Successfully signed and verified.");
        }
        awsKmsKey.close();
    }

}
