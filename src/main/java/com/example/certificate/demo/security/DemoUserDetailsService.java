package com.example.certificate.demo.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

public class DemoUserDetailsService implements UserDetailsService {
  private static final Logger LOGGER = LoggerFactory.getLogger(DemoUserDetailsService.class);

  private final PasswordEncoder passwordEncoder;

  public DemoUserDetailsService(PasswordEncoder passwordEncoder) {
    this.passwordEncoder = passwordEncoder;
  }

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

    LOGGER.debug("Got username {}", username);

    if ("myuser".equals(username)) {
      return User.withUsername("myuser")
          .passwordEncoder(passwordEncoder::encode)
          .password("none")
          .roles("USER")
          .build();
    } else {
      throw new UsernameNotFoundException(String.format("No user found for %s", username));
    }
  }
}
