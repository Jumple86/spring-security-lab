package org.ian.springsecuritylab.controller;

import com.google.code.kaptcha.Producer;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.ian.springsecuritylab.utils.VerifyCode;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

@RestController
public class VerifyCodeController {

    private final Producer producer;

    public VerifyCodeController(Producer producer) {
        this.producer = producer;
    }

    @GetMapping("getVerifyCode")
    public ResponseEntity<byte[]> getVerifyCode(HttpServletRequest request) throws IOException {
        String text = producer.createText();
        HttpSession session = request.getSession();
        session.setAttribute("verify_code", text);

        // 将图像转换为字节数组
        BufferedImage image = producer.createImage(text);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(image, "JPEG", baos);
        byte[] imageData = baos.toByteArray();

        // 设置响应头
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.IMAGE_JPEG);
        headers.setCacheControl("no-cache, no-store, must-revalidate");
        headers.setPragma("no-cache");
        headers.setExpires(0);

        return new ResponseEntity<>(imageData, headers, HttpStatus.OK);
    }
}
