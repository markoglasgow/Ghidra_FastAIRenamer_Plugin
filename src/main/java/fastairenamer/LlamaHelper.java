package fastairenamer;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public class LlamaHelper {

    private final HttpClient http;
    private final String endpoint;
    private final String apiKey;
    private final String model;

    private String systemPrompt = null;
    private double temperature = 1.0;
    private int maxTokens = 16384;

    public LlamaHelper(String baseUrl, String apiKey, String model) {
        this.apiKey = apiKey;
        this.model = model;
        this.endpoint = baseUrl.replaceAll("/+$", "") + "/v1/chat/completions";
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    public LlamaHelper setSystemPrompt(String systemPrompt) {
        this.systemPrompt = systemPrompt;
        return this;
    }

    public LlamaHelper setTemperature(double temperature) {
        this.temperature = temperature;
        return this;
    }

    public LlamaHelper setMaxTokens(int maxTokens) {
        this.maxTokens = maxTokens;
        return this;
    }

    public String getResponse(String userMessage) throws IOException, InterruptedException {
        JSONArray messages = new JSONArray();

        if (systemPrompt != null && !systemPrompt.isBlank()) {
            messages.put(new JSONObject()
                    .put("role", "system")
                    .put("content", systemPrompt));
        }
        

        messages.put(new JSONObject()
                .put("role", "user")
                .put("content", userMessage));

        String body = new JSONObject()
                .put("model", model)
                .put("messages", messages)
                .put("temperature", temperature)
                .put("max_tokens", maxTokens)
                .toString();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(endpoint))
                .timeout(Duration.ofSeconds(120))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + apiKey)
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IOException("API error " + response.statusCode() + ": " + response.body());
        }

        return new JSONObject(response.body())
                .getJSONArray("choices")
                .getJSONObject(0)
                .getJSONObject("message")
                .getString("content");
    }
}
