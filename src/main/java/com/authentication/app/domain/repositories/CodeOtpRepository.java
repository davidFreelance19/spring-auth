package com.authentication.app.domain.repositories;

import java.util.Date;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import com.authentication.app.domain.entities.CodeOtpEntity;
import com.authentication.app.domain.entities.UserEntity;

@Repository
public interface  CodeOtpRepository extends CrudRepository<CodeOtpEntity, Long> {
    CodeOtpEntity findByUserAndCode(UserEntity user, String code);
    CodeOtpEntity findByUser(UserEntity user);
    void deleteByCreatedAtBefore(Date date);
}
