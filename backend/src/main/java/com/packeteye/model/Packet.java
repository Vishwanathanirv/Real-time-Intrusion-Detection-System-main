package com.packeteye.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;

@Entity
@Table(name = "packets")
public class Packet {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String timestamp;

    @Column(name = "src_ip")
    @JsonProperty("srcIp")
    private String srcIp;

    @Column(name = "dest_ip")
    @JsonProperty("destIp")
    private String destIp;

    private String protocol;
    private int length;
    private int flags;

    private String status;   
    private String reason;   
    private String attackType; 

    public Packet() {}

    public Packet(String timestamp, String srcIp, String destIp, String protocol, int length,
                  int flags, String status, String reason, String attackType) {
        this.timestamp = timestamp;
        this.srcIp = srcIp;
        this.destIp = destIp;
        this.protocol = protocol;
        this.length = length;
        this.flags = flags;
        this.status = status;
        this.reason = reason;
        this.attackType = attackType;
    }

    public Long getId() { return id; }
    public String getTimestamp() { return timestamp; }
    public String getSrcIp() { return srcIp; }
    public String getDestIp() { return destIp; }
    public String getProtocol() { return protocol; }
    public int getLength() { return length; }
    public int getFlags() { return flags; }
    public String getStatus() { return status; }
    public String getReason() { return reason; }
    public String getAttackType() { return attackType; }

    public void setId(Long id) { this.id = id; }
    public void setTimestamp(String timestamp) { this.timestamp = timestamp; }
    public void setSrcIp(String srcIp) { this.srcIp = srcIp; }
    public void setDestIp(String destIp) { this.destIp = destIp; }
    public void setProtocol(String protocol) { this.protocol = protocol; }
    public void setLength(int length) { this.length = length; }
    public void setFlags(int flags) { this.flags = flags; }
    public void setStatus(String status) { this.status = status; }
    public void setReason(String reason) { this.reason = reason; }
    public void setAttackType(String attackType) { this.attackType = attackType; }
}