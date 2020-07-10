package com.adiwal.auth

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity

@SpringBootApplication
@EnableGlobalMethodSecurity(prePostEnabled = true)
class AuthApplication

fun main(args: Array<String>) {
    runApplication<AuthApplication>(*args)
}