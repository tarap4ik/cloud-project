package ru.lip.itc.service2.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/new")
public class ClientController {

    @GetMapping("/test")
    public String test() {
        return "service2";
    }

}
