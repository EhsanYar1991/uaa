package com.mciws.uaa.domain.redis;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serializable;

@RedisHash(timeToLive = 1000 * 60 * 60 * 20, value = "OnlineUser")
@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class OnlineUser implements Serializable {

    @Id
    private String id;
    private UserDetails userDetails;


    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public UserDetails getUserDetails() {
        return userDetails;
    }

    public void setUserDetails(UserDetails userDetails) {
        this.userDetails = userDetails;
    }

}
