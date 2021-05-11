package com.mciws.uaa.repository.redis;

import com.mciws.uaa.domain.redis.OnlineUser;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface OnlineUserRepository extends CrudRepository<OnlineUser, String> {

}
