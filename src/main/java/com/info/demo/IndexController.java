package com.info.demo;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;


@Controller
public class IndexController {

    @PostMapping("/processForm")
    public String processForm(@RequestParam String input, Model model, @RequestParam String inputMethod, @RequestParam String inputMode, @RequestParam String inputPadding) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        String output ="";

        //Key generating--------------------------------------------------------
        byte[] keyBytes = Hex.decode("000102030405060708090a0b0c0d0e0f");
        SecretKeySpec key = new SecretKeySpec(keyBytes, inputMethod);

        //Cipher----------------------------------------------------------------
        String c = inputMethod + "/" + inputMode + "/" + inputPadding + "Padding";
        Cipher cipher = Cipher.getInstance(c, "BC");

        //Input-----------------------------------------------------------------
        byte[] byteInput = input.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
        output = output + "Input: " + Hex.toHexString(byteInput);

        //Encrypt---------------------------------------------------------------
        cipher.init(Cipher.ENCRYPT_MODE, key);
        //If CBC
            byte[] iv = null;
            if(inputMode.equals("CBC")) iv = cipher.getIV();
        byte[] byteOutput = cipher.doFinal(byteInput);
        output = output + "Encrypted: " + Hex.toHexString(byteOutput);

        //Decrypt
        if(inputMode.equals("CBC")){
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            byte[] finalOutput = new byte[cipher.getOutputSize(byteOutput.length)];
            int len = cipher.update(byteOutput, 0, byteOutput.length, finalOutput, 0);
            len += cipher.doFinal(finalOutput, len);
            output = output + "Decrypted: " + Hex.toHexString(Arrays.copyOfRange(finalOutput, 0, len));
        }else{
            cipher.init(Cipher.DECRYPT_MODE, key);
            output = output + "Decrypted: " + cipher.doFinal(byteOutput);
        }
        

        model.addAttribute("output", output);
        return "index";
    }

}