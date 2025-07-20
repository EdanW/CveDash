import axios, { AxiosResponse } from 'axios';
import { NvdCveResponse, NvdCveParams } from './types';
import { convertToInternalFormat } from './utils';

export class NvdWrapper {
  private baseUrl = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
  private apiKey?: string;

  constructor(apiKey?: string) {
    this.apiKey = apiKey;
  }

  /**
   * Get a specific CVE by its ID
   * @param cveId - The CVE ID (e.g., "CVE-2023-1234")
   * @returns Promise<NvdCveResponse>
   */
  async getCve(cveId: string): Promise<NvdCveResponse> {
    const params: NvdCveParams = { cveId };
    return this.makeRequest(params);
  }

  /**
   * Search for CVEs with various filters
   * @param params - Search parameters
   * @returns Promise<NvdCveResponse>
   */
  async searchCves(params: NvdCveParams): Promise<NvdCveResponse> {
    return this.makeRequest(params);
  }

  /**
   * Get CVEs by CVSS severity
   * @param severity - CVSS severity level
   * @param version - CVSS version (v2, v3, v4)
   * @returns Promise<NvdCveResponse>
   */
  async getCvesBySeverity(
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL',
    version: 'v2' | 'v3' | 'v4' = 'v3'
  ): Promise<NvdCveResponse> {
    const params: NvdCveParams = {};
    
    switch (version) {
      case 'v2':
        params.cvssV2Severity = severity as 'LOW' | 'MEDIUM' | 'HIGH';
        break;
      case 'v3':
        params.cvssV3Severity = severity;
        break;
      case 'v4':
        params.cvssV4Severity = severity;
        break;
    }
    
    return this.makeRequest(params);
  }

  /**
   * Get CVEs by date range
   * @param startDate - Start date in ISO format
   * @param endDate - End date in ISO format
   * @returns Promise<NvdCveResponse>
   */
  async getCvesByDateRange(startDate: string, endDate: string): Promise<NvdCveResponse> {
    const params: NvdCveParams = {
      pubStartDate: startDate,
      pubEndDate: endDate
    };
    return this.makeRequest(params);
  }

  /**
   * Get CVEs by keyword search
   * @param keyword - Search keyword
   * @param exactMatch - Whether to use exact match (not supported in v2.0)
   * @returns Promise<NvdCveResponse>
   */
  async searchCvesByKeyword(keyword: string, exactMatch: boolean = false): Promise<NvdCveResponse> {
    const params: NvdCveParams = {
      keywordSearch: keyword
      // Note: keywordExactMatch is not supported in NVD API v2.0
    };
    return this.makeRequest(params);
  }

  /**
   * Get CVEs by CPE name
   * @param cpeName - CPE name (e.g., "cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*")
   * @returns Promise<NvdCveResponse>
   */
  async getCvesByCpe(cpeName: string): Promise<NvdCveResponse> {
    const params: NvdCveParams = { cpeName };
    return this.makeRequest(params);
  }

  /**
   * Get CVEs that are in CISA KEV (Known Exploited Vulnerabilities)
   * @returns Promise<NvdCveResponse>
   */
  async getCisaKevCves(): Promise<NvdCveResponse> {
    const params: NvdCveParams = { hasKev: true };
    return this.makeRequest(params);
  }

  /**
   * Make a request to the NVD API
   * @param params - Query parameters
   * @returns Promise<NvdCveResponse>
   */
  private async makeRequest(params: NvdCveParams): Promise<NvdCveResponse> {
    try {
      const config = {
        headers: {
          'User-Agent': 'CveDash/1.0',
          ...(this.apiKey && { 'apiKey': this.apiKey })
        }
      };

      const response: AxiosResponse<NvdCveResponse> = await axios.get(
        this.baseUrl,
        {
          params,
          ...config
        }
      );

      return response.data;
    } catch (error) {
      if (axios.isAxiosError(error)) {
        throw new Error(`NVD API Error: ${error.response?.status} - ${error.response?.statusText}`);
      }
      throw new Error(`Unexpected error: ${error}`);
    }
  }

  /**
   * Convert NVD CVE to our internal CVE format
   * @param nvdCve - NVD CVE object
   * @returns CVE object in our format
   */
  static convertToInternalFormat = convertToInternalFormat;
} 