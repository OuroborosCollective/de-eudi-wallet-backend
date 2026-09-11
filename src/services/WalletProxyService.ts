import axios, { AxiosError, AxiosInstance, AxiosRequestConfig } from 'axios';
import { z } from 'zod';

export class WalletProxyService {
  private client: AxiosInstance;

  constructor() {
    const baseURL = process.env.UPSTREAM_EUDI_URL || 'https://api.eudiwallet.de.example.com';
    const apiKey = process.env.UPSTREAM_EUDI_API_KEY || '';

    this.client = axios.create({
      baseURL,
      timeout: 10000,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
      }
    });

    // Add interceptor for runtime validation of upstream response
    this.client.interceptors.response.use(
      (response) => {
        // Here you can do structural validation, e.g., using Zod
        return response;
      },
      (error: AxiosError) => {
        console.error(`[WalletProxyService] Upstream Error: ${error.message} - URL: ${error.config?.url}`);
        return Promise.reject(error);
      }
    );
  }

  /**
   * Forward a POST request
   */
  async forwardPost<T>(path: string, body: any, customHeaders: Record<string, string> = {}): Promise<T> {
    const config: AxiosRequestConfig = {
      headers: { ...customHeaders }
    };
    const response = await this.client.post<T>(path, body, config);
    return response.data;
  }

  /**
   * Forward a GET request
   */
  async forwardGet<T>(path: string, customHeaders: Record<string, string> = {}): Promise<T> {
    const config: AxiosRequestConfig = {
      headers: { ...customHeaders }
    };
    const response = await this.client.get<T>(path, config);
    return response.data;
  }

  /**
   * Forward a DELETE request
   */
  async forwardDelete<T>(path: string, customHeaders: Record<string, string> = {}): Promise<T> {
    const config: AxiosRequestConfig = {
      headers: { ...customHeaders }
    };
    const response = await this.client.delete<T>(path, config);
    return response.data;
  }
}

export const proxyService = new WalletProxyService();
