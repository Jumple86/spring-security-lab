package org.ian.springsecuritylab.config;

import com.google.code.kaptcha.Producer;
import com.google.code.kaptcha.impl.DefaultKaptcha;
import com.google.code.kaptcha.util.Config;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Properties;

@Configuration
public class VerifyCodeConfig {

    @Bean
    public Producer verifyCode() {
        DefaultKaptcha defaultKaptcha = new DefaultKaptcha();

        Properties properties = new Properties();
        properties.setProperty("kaptcha.textproducer.char.string", "0123456789abcdefghijklmnopqrstuvwxyz");
        properties.setProperty("kaptcha.textproducer.char.length", "4");

        Config config = new Config(properties);
        defaultKaptcha.setConfig(config);

        return defaultKaptcha;
    }
}
