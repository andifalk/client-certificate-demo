package com.example.certificate.demo.web;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/")
public class DemoController {

  @GetMapping
  public String index(@AuthenticationPrincipal User user, Model model) {
    model.addAttribute("username", user.getUsername());
    return "index";
  }
}
