/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.wso2.carbon.cloud.deployment.secret.handler;

import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.secretsmanager.AWSSecretsManager;
import com.amazonaws.services.secretsmanager.AWSSecretsManagerClientBuilder;
import com.amazonaws.services.secretsmanager.model.DecryptionFailureException;
import com.amazonaws.services.secretsmanager.model.GetSecretValueRequest;
import com.amazonaws.services.secretsmanager.model.GetSecretValueResult;
import com.amazonaws.services.secretsmanager.model.InternalServiceErrorException;
import com.amazonaws.services.secretsmanager.model.InvalidParameterException;
import com.amazonaws.services.secretsmanager.model.InvalidRequestException;
import com.amazonaws.services.secretsmanager.model.ResourceNotFoundException;
import org.wso2.carbon.securevault.DefaultSecretCallbackHandler;
import org.wso2.securevault.secret.SingleSecretCallback;

import java.nio.ByteBuffer;
import java.util.Base64;

public class CustomSecretCallbackHandler extends DefaultSecretCallbackHandler {

    public void handleSingleSecretCallback(SingleSecretCallback singleSecretCallback) {

        singleSecretCallback.setSecret(getSecret());
    }

    // Use this code snippet in your app.
    // If you need more information about configurations or implementing the sample code, visit the AWS docs:
    // https://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/java-dg-samples.html#prerequisites

    private String getSecret() {

        String secretName = "keystorePass";
        AWSSecretsManager client = AWSSecretsManagerClientBuilder.standard().withRegion("us-east-1").build();
        String secret, decodedBinarySecret;
        GetSecretValueRequest getSecretValueRequest = new GetSecretValueRequest().withSecretId(secretName);
        GetSecretValueResult getSecretValueResult = null;

        try {
            getSecretValueResult = client.getSecretValue(getSecretValueRequest);
        } catch (DecryptionFailureException e) {
            // Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            // Deal with the exception here, and/or rethrow at your discretion.
            throw e;
        } catch (InternalServiceErrorException e) {
            // An error occurred on the server side.
            // Deal with the exception here, and/or rethrow at your discretion.
            throw e;
        } catch (InvalidParameterException e) {
            // You provided an invalid value for a parameter.
            // Deal with the exception here, and/or rethrow at your discretion.
            throw e;
        } catch (InvalidRequestException e) {
            // You provided a parameter value that is not valid for the current state of the resource.
            // Deal with the exception here, and/or rethrow at your discretion.
            throw e;
        } catch (ResourceNotFoundException e) {
            // We can't find the resource that you asked for.
            // Deal with the exception here, and/or rethrow at your discretion.
            throw e;
        }

        // Decrypts secret using the associated KMS CMK.
        // Depending on whether the secret is a string or binary, one of these fields will be populated.
        if (getSecretValueResult.getSecretString() != null) {
            secret = getSecretValueResult.getSecretString();
            return secret;
        } else {
            decodedBinarySecret = new String(
                    Base64.getDecoder().decode(getSecretValueResult.getSecretBinary()).array());
            return decodedBinarySecret;
        }
    }

    public String getSecret(String secretName, String region) {
        String endpoint =("secretsmanager." + region + ".amazonaws.com");
        AwsClientBuilder.EndpointConfiguration config = new AwsClientBuilder.EndpointConfiguration(endpoint, region);
        AWSSecretsManagerClientBuilder clientBuilder = AWSSecretsManagerClientBuilder.standard();
        clientBuilder.setEndpointConfiguration(config);
        AWSSecretsManager client = clientBuilder.build();
        String secret = null;
        ByteBuffer binarySecretData;
        GetSecretValueRequest getSecretValueRequest = new GetSecretValueRequest().withSecretId(secretName);
        GetSecretValueResult getSecretValueResponse = null;
        try {
            getSecretValueResponse = client.getSecretValue(getSecretValueRequest);

        } catch(ResourceNotFoundException e) {
            System.out.println("The requested secret " + secretName + " was not found");
        } catch (InvalidRequestException e) {
            System.out.println("The request was invalid due to: " + e.getMessage());
        } catch (InvalidParameterException e) {
            System.out.println("The request had invalid params: " + e.getMessage());
        }

        if(getSecretValueResponse == null) {
            return "";
        }

        // Decrypted secret using the associated KMS CMK
        // Depending on whether the secret was a string or binary, one of these fields will be populated
        if(getSecretValueResponse.getSecretString() != null) {
            secret = getSecretValueResponse.getSecretString();
        }
        else {
            binarySecretData = getSecretValueResponse.getSecretBinary();
        }

        // Your code goes here.
        System.out.println("Secret Name : " + secretName + "\t Secret Value : " + secret + "\n");
        return secret;
    }
}