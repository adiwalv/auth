package com.adiwal.auth.entity

import org.bson.types.ObjectId
import org.springframework.data.annotation.Id


data class Users(@Id val id : String? = null,
val username : String, val password : String)