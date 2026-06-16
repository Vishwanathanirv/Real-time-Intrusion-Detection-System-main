package com.packeteye.repository;

import com.packeteye.model.Packet;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface PacketRepository extends JpaRepository<Packet, Long> {

   
    List<Packet> findTop500ByOrderByTimestampDesc();

    
    @Query("SELECT p.status, COUNT(p) FROM Packet p GROUP BY p.status")
    List<Object[]> countByStatus();

   
    @Query("SELECT p.attackType, COUNT(p) FROM Packet p " +
           "WHERE p.attackType IS NOT NULL AND p.attackType <> '' " +
           "GROUP BY p.attackType")
    List<Object[]> countByAttackType();

    
    @Query("SELECT p.protocol, COUNT(p) FROM Packet p GROUP BY p.protocol")
    List<Object[]> countByProtocol();

   
    @Query("SELECT p FROM Packet p WHERE LOWER(p.status) = 'anomaly' ORDER BY p.timestamp DESC LIMIT 10")
    List<Packet> findRecentAnomalies();
}