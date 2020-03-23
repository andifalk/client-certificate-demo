package com.example.certificate.demo.web;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.http.HttpStatus.OK;

@RestController
@RequestMapping("/api")
public class DemoRestController {

  @ResponseStatus(OK)
  @GetMapping
  public String api(@AuthenticationPrincipal User user) {
    return "it works for " + user.getUsername();
  }
}
