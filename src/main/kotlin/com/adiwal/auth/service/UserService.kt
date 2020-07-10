package com.adiwal.auth.service

import com.adiwal.auth.domain.User
import java.util.*

interface UserService {
    fun tryCreate(user: User): Optional<User>
    fun findByUsername(username: String): Optional<User>
}