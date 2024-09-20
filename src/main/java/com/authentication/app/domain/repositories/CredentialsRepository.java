package com.authentication.app.domain.repositories;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import com.authentication.app.domain.entities.CredentialEntity;

@Repository
public interface CredentialsRepository extends CrudRepository<CredentialEntity, Long>{
    public CredentialEntity findByEmail(String email);
}
