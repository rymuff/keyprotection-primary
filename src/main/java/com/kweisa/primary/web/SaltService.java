package com.kweisa.primary.web;

import retrofit2.Call;
import retrofit2.http.GET;
import retrofit2.http.POST;
import retrofit2.http.Query;

public interface SaltService {
    @POST("/salt")
    Call<Void> createUser(@Query("username") String username,
                    @Query("password") String password,
                    @Query("salt") String salt);

    @GET("/salt")
    Call<String> readSalt(@Query("username") String username,
                          @Query("password") String password);
}
