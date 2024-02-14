package org.ian.springsecuritylab.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping("/hello")
    public String hello() {
        return "Hello world";
    }

    @GetMapping("/loginSuccess")
    public String loginSuccess() {
        return "success";
    }

    @GetMapping("/loginFail")
    public String loginFail() {
        return "failed";
    }

    @GetMapping("/admin/hello")
    public String admin() {
        return "admin";
    }

    @GetMapping("/user/hello")
    public String user() {
        return "user";
    }
}
