package com.packeteye.controller;

import java.io.*;
import java.util.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import com.packeteye.model.Packet;
import com.packeteye.repository.PacketRepository;

@CrossOrigin(origins = "http://localhost:3000")
@RestController
@RequestMapping("/api")
public class PacketController {

    @Autowired
    private PacketRepository packetRepository;

    private Process analysisProcess;
    private Process simulationProcess;
    private Process telegramProcess;

    private Process runPythonScript(String pythonExe, String scriptPath, String workingDir) throws IOException {
        System.out.println("🚀 Executing Python script:\n   " + scriptPath);

        List<String> command = new ArrayList<>();
        command.add(pythonExe);
        command.add(scriptPath);

        ProcessBuilder pb = new ProcessBuilder(command);
        pb.directory(new File(workingDir));
        pb.redirectErrorStream(true);

        Map<String, String> env = pb.environment();
        env.put("PYTHONIOENCODING", "utf-8");
        env.put("PYTHONUTF8", "1");

        Process process = pb.start();

        new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), "UTF-8"))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println("[PYTHON] " + line);
                }
            } catch (IOException e) {
                System.err.println("Error reading Python process output: " + e.getMessage());
            }
        }).start();

        return process;
    }

    @GetMapping("/start-capture")
    public String startCapture() {
        try {
            if (analysisProcess != null && analysisProcess.isAlive()) {
                return " analysis.py is already running.";
            }
            String pythonExe = "D:\\softwares\\python.exe";
            String workingDir = "D:\\Packeteye\\Chanakya_Shield";
            String scriptPath = workingDir + "\\mlmodel\\analysis.py";

            analysisProcess = runPythonScript(pythonExe, scriptPath, workingDir);
            return "✅ Real-time packet capture started successfully ";
        } catch (IOException e) {
            e.printStackTrace();
            return " Failed to start analysis.py: " + e.getMessage();
        }
    }

    @GetMapping("/simulate-attack")
    public String simulateAttack(@RequestParam(required = false) String type) {
        try {
            if (simulationProcess != null && simulationProcess.isAlive()) {
                return " Simulation is already running.";
            }
            String pythonExe = "D:\\softwares\\python.exe";
            String workingDir = "D:\\Packeteye\\Chanakya_Shield";
            String scriptPath = workingDir + "\\Testing\\inject_attacks.py";

            // Build command with attack type if provided
            List<String> command = new ArrayList<>();
            command.add(pythonExe);
            command.add(scriptPath);
            if (type != null && !type.isEmpty()) {
                command.add(type);
            }

            ProcessBuilder pb = new ProcessBuilder(command);
            pb.directory(new File(workingDir));
            pb.redirectErrorStream(true);

            Map<String, String> env = pb.environment();
            env.put("PYTHONIOENCODING", "utf-8");
            env.put("PYTHONUTF8", "1");

            simulationProcess = pb.start();

            new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(simulationProcess.getInputStream(), "UTF-8"))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        System.out.println("[PYTHON] " + line);
                    }
                } catch (IOException e) {
                    System.err.println("Error reading Python process output: " + e.getMessage());
                }
            }).start();

            String attackName = (type != null) ? type.toUpperCase() : "ALL";
            return "🎯 " + attackName + " attack simulation started successfully";
        } catch (IOException e) {
            e.printStackTrace();
            return " Failed to start simulation: " + e.getMessage();
        }
    }

    @GetMapping("/start-telegram")
    public String startTelegramAlerts() {
        try {
            if (telegramProcess != null && telegramProcess.isAlive()) {
                return " Telegram service already running.";
            }
            String pythonExe = "D:\\softwares\\python.exe";
            String workingDir = "D:\\Packeteye\\Chanakya_Shield";
            String scriptPath = workingDir + "\\Testing\\telegram_alert_service_whitelist.py";

            telegramProcess = runPythonScript(pythonExe, scriptPath, workingDir);
            return "📲 Telegram alert service started successfully!";
        } catch (IOException e) {
            e.printStackTrace();
            return " Failed to start Telegram alert service: " + e.getMessage();
        }
    }

    @GetMapping("/stop-capture")
    public String stopCapture() {
        if (analysisProcess != null && analysisProcess.isAlive()) {
            analysisProcess.destroy();
            return " Packet capture stopped successfully.";
        }
        return " No active capture process found.";
    }

    @GetMapping("/stop-simulation")
    public String stopSimulation() {
        if (simulationProcess != null && simulationProcess.isAlive()) {
            simulationProcess.destroy();
            return " Simulation stopped successfully.";
        }
        return " No active simulation process found.";
    }

    @GetMapping("/stop-telegram")
    public String stopTelegram() {
        if (telegramProcess != null && telegramProcess.isAlive()) {
            telegramProcess.destroy();
            return " Telegram alert service stopped successfully.";
        }
        return " No active telegram process found.";
    }

    @GetMapping("/status")
    public Map<String, String> getStatus() {
        Map<String, String> status = new HashMap<>();
        status.put("analysis", (analysisProcess != null && analysisProcess.isAlive()) ? "🟢 Running" : "🔴 Stopped");
        status.put("simulation",
                (simulationProcess != null && simulationProcess.isAlive()) ? "🟢 Running" : "🔴 Stopped");
        status.put("telegram", (telegramProcess != null && telegramProcess.isAlive()) ? "🟢 Running" : "🔴 Stopped");
        return status;
    }

    @PostMapping("/packets")
    public Packet addPacket(@RequestBody Packet packet) {
        return packetRepository.save(packet);
    }

    @GetMapping("/packets")
    public List<Packet> getAllPackets() {
        return packetRepository.findTop500ByOrderByTimestampDesc();
    }

    @DeleteMapping("/packets")
    public Map<String, Object> clearAllPackets() {
        try {
            long count = packetRepository.count();
            packetRepository.deleteAll();
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "Successfully cleared " + count + " packets from database");
            response.put("deletedCount", count);
            return response;
        } catch (Exception e) {
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "Failed to clear packets: " + e.getMessage());
            return response;
        }
    }

    @GetMapping("/packets/summary")
    public Map<String, Object> getSummary() {
        long totalPackets = packetRepository.count();

        List<Object[]> statusCounts = packetRepository.countByStatus();
        long normal = 0, anomalies = 0;
        for (Object[] row : statusCounts) {
            String status = (String) row[0];
            long count = (long) row[1];
            if ("Anomaly".equalsIgnoreCase(status))
                anomalies = count;
            else if ("Normal".equalsIgnoreCase(status))
                normal = count;
        }

        List<Object[]> attackCounts = packetRepository.countByAttackType();
        long totalAttacks = attackCounts.stream()
                .filter(row -> row[0] != null && !row[0].toString().equalsIgnoreCase("BENIGN"))
                .mapToLong(row -> (long) row[1]).sum();

        double anomalyRate = (totalPackets == 0) ? 0 : ((double) anomalies / totalPackets) * 100.0;

        Map<String, Object> summary = new HashMap<>();
        summary.put("totalPackets", totalPackets);
        summary.put("normalPackets", normal);
        summary.put("anomalyPackets", anomalies);
        summary.put("totalAttacks", totalAttacks);
        summary.put("anomalyRate", Math.round(anomalyRate * 100.0) / 100.0);
        return summary;
    }

    @GetMapping("/packets/timeline")
    public List<Map<String, Object>> getTimeline() {
        List<Packet> packets = packetRepository.findTop500ByOrderByTimestampDesc();
        List<Map<String, Object>> timeline = new ArrayList<>();

        for (Packet p : packets) {
            Map<String, Object> entry = new HashMap<>();
            entry.put("timestamp", p.getTimestamp());
            entry.put("status", p.getStatus());
            entry.put("attackType", p.getAttackType());
            timeline.add(entry);
        }
        return timeline;
    }

    @GetMapping("/packets/protocol-summary")
    public List<Map<String, Object>> getProtocolSummary() {
        List<Object[]> results = packetRepository.countByProtocol();
        List<Map<String, Object>> summary = new ArrayList<>();
        for (Object[] row : results) {
            summary.add(Map.of("protocol", row[0], "count", row[1]));
        }
        return summary;
    }

    @GetMapping("/packets/attack-summary")
    public List<Map<String, Object>> getAttackSummary() {
        List<Object[]> results = packetRepository.countByAttackType();
        List<Map<String, Object>> summary = new ArrayList<>();

        for (Object[] row : results) {
            String attack = (String) row[0];
            Long count = (Long) row[1];
            if (attack != null && !attack.isBlank()) {
                summary.add(Map.of("attack", attack, "count", count));
            }
        }

        return summary;
    }

    @GetMapping("/packets/features")
    public List<String> getSelectedFeatures() {
        File file = new File("D:\\Packeteye\\Chanakya_Shield\\selected_features.json");
        if (!file.exists()) {
            return List.of("No features selected yet.");
        }
        try {
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            return mapper.readValue(file, List.class);
        } catch (IOException e) {
            return List.of("Error loading features: " + e.getMessage());
        }
    }

    @RequestMapping("/error")
    public String handleError() {
        return "Invalid request method or path.";
    }
}