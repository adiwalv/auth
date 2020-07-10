package com.adiwal.auth.service

import com.adiwal.auth.domain.Role
import java.util.*

interface RoleService {
    fun tryCreate(role: Role): Optional<Role>
    fun findByName(name: String): Optional<Role>
}