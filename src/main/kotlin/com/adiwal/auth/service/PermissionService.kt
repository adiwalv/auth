package com.adiwal.auth.service

import com.adiwal.auth.domain.Permission
import java.util.*

interface PermissionService {
    fun tryCreate(permission: Permission): Optional<Permission>
    fun findByName(name: String): Optional<Permission>
}