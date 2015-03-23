package net.hackosis.semfor.parsers;

import com.kanishka.virustotal.dto.FileScanReport;
import com.kanishka.virustotal.dto.IPAddressReport;
import com.kanishka.virustotal.dto.IPAddressResolution;
import com.kanishka.virustotal.dto.Sample;
import com.kanishka.virustotal.dto.URL;
import com.kanishka.virustotal.dto.VirusScanInfo;
import com.kanishka.virustotal.exception.APIKeyNotFoundException;
import com.kanishka.virustotal.exception.QuotaExceededException;
import com.kanishka.virustotal.exception.UnauthorizedAccessException;
import com.kanishka.virustotalv2.VirusTotalConfig;
import com.kanishka.virustotalv2.VirustotalPublicV2;
import com.kanishka.virustotalv2.VirustotalPublicV2Impl;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;


/**
 *
 * @author root
 */
public class VirusTotalParser {
    
    private String API_KEY = "71b01ef25f1ae22ffd640c2f64d3a70dfd07f8f3132c92c5fe0b73e260d1212e";
    private VirustotalPublicV2 virusTotalRef;
    
    public VirusTotalParser(){
       try{
           VirusTotalConfig.getConfigInstance().setVirusTotalAPIKey(API_KEY);
           virusTotalRef = new VirustotalPublicV2Impl();
       } catch (APIKeyNotFoundException ex){
           System.err.println("API Key Not Found: " + ex.getMessage());
       }
    }
    
    private FileScanReport[] getFileScanReports(String[] files){
        FileScanReport[] report = null;
        try{
           report = virusTotalRef.getScanReports(files);
        } catch (IOException ex){
            System.err.println("I/O Error: " + ex.getMessage());
        } catch (UnauthorizedAccessException ex){
            System.err.println("Unauthorized Access: " + ex.getMessage());
        } catch (QuotaExceededException ex){
            System.err.println("Quota Exceeded. Try again later: " + ex.getMessage());
        } catch (Exception ex){
            System.err.println("Generic Exception: " + ex.getMessage());
        }
        return report;
    }
    
    private FileScanReport[] getUrlScanReports(String[] urls){
        FileScanReport[] reports = null;
        try{
            // Don't ask for VirusTotal to scan previously unknown URLs
            reports = virusTotalRef.getUrlScanReport(urls, false);
        } catch (IOException ex){
            System.err.println("I/O Error: " + ex.getMessage());
        } catch (UnauthorizedAccessException ex){
            System.err.println("Unauthorized Access: " + ex.getMessage());
        } catch (QuotaExceededException ex){
            System.err.println("Quota Exceeded. Try again later: " + ex.getMessage());
        } catch (Exception ex){
            System.err.println("Generic Exception: " + ex.getMessage());
        }
        return reports;
    }
    
    private List<IPAddressReport> getIPAddressReport(String[] ips){
        IPAddressReport report = null;
        List<IPAddressReport> ipReports = new ArrayList<IPAddressReport>();
        try{
            for (String ip : ips){
                report = virusTotalRef.getIPAddresReport(ip);
                ipReports.add(report);
            }
        } catch (IOException ex){
            System.err.println("I/O Error: " + ex.getMessage());
        } catch (UnauthorizedAccessException ex){
            System.err.println("Unauthorized Access: " + ex.getMessage());
        } catch (QuotaExceededException ex){
            System.err.println("Quota Exceeded. Try again later: " + ex.getMessage());
        } catch (Exception ex){
            System.err.println("Generic Exception: " + ex.getMessage());
        }
        return ipReports;
    }
    
    private void printScanReport(FileScanReport report){
        if (report != null){
            System.out.println("MD5 :\t" + report.getMd5());
            System.out.println("Perma link :\t" + report.getPermalink());
            System.out.println("Resource :\t" + report.getResource());
            System.out.println("Scan Date :\t" + report.getScanDate());
            System.out.println("Scan Id :\t" + report.getScanId());
            System.out.println("SHA1 :\t" + report.getSha1());
            System.out.println("SHA256 :\t" + report.getSha256());
            System.out.println("Verbose Msg :\t" + report.getVerboseMessage());
            System.out.println("Response Code :\t" + report.getResponseCode());
            System.out.println("Positives :\t" + report.getPositives());
            System.out.println("Total :\t" + report.getTotal());

            Map<String, VirusScanInfo> scans = report.getScans();
            for (String key : scans.keySet()) {
                VirusScanInfo virusInfo = scans.get(key);
                System.out.println("Scanner : " + key);
                System.out.println("\t\t Resut : " + virusInfo.getResult());
                System.out.println("\t\t Update : " + virusInfo.getUpdate());
                System.out.println("\t\t Version :" + virusInfo.getVersion());
            }
        }
    }
    
    private void printIPReport(IPAddressReport report){
        if (report != null){
             System.out.println("___IP Rport__");

            Sample[] communicatingSamples = report.getDetectedCommunicatingSamples();
            if (communicatingSamples != null) {
                System.out.println("Communicating Samples");
                for (Sample sample : communicatingSamples) {
                    System.out.println("SHA256 : " + sample.getSha256());
                    System.out.println("Date : " + sample.getDate());
                    System.out.println("Positives : " + sample.getPositives());
                    System.out.println("Total : " + sample.getTotal());
                }
            }

            Sample[] detectedDownloadedSamples = report.getDetectedDownloadedSamples();
            if (detectedDownloadedSamples != null) {
                System.out.println("Detected Downloaded Samples");
                for (Sample sample : detectedDownloadedSamples) {
                    System.out.println("SHA256 : " + sample.getSha256());
                    System.out.println("Date : " + sample.getDate());
                    System.out.println("Positives : " + sample.getPositives());
                    System.out.println("Total : " + sample.getTotal());
                }
            }

            URL[] urls = report.getDetectedUrls();
            if (urls != null) {
                System.out.println("Detected URLs");
                for (URL url : urls) {
                    System.out.println("URL : " + url.getUrl());
                    System.out.println("Positives : " + url.getPositives());
                    System.out.println("Total : " + url.getTotal());
                    System.out.println("Scan Date" + url.getScanDate());
                }
            }

            IPAddressResolution[] resolutions = report.getResolutions();
            if (resolutions != null) {
                System.out.println("Resolutions");
                for (IPAddressResolution resolution : resolutions) {
                    System.out.println("HostName : " + resolution.getHostName());
                    System.out.println("Last Resolved : " + resolution.getLastResolved());
                }
            }

            Sample[] unDetectedDownloadedSamples = report.getUndetectedDownloadedSamples();
            if (unDetectedDownloadedSamples != null) {
                System.out.println("Undetected Downloaded Samples");
                for (Sample sample : unDetectedDownloadedSamples) {
                    System.out.println("SHA256 : " + sample.getSha256());
                    System.out.println("Date : " + sample.getDate());
                    System.out.println("Positives : " + sample.getPositives());
                    System.out.println("Total : " + sample.getTotal());
                }
            }

            Sample[] unDetectedCommunicatingSamples = report.getUndetectedCommunicatingSamples();
            if (unDetectedCommunicatingSamples != null) {
                System.out.println("Undetected Communicating Samples");
                for (Sample sample : unDetectedCommunicatingSamples) {
                    System.out.println("SHA256 : " + sample.getSha256());
                    System.out.println("Date : " + sample.getDate());
                    System.out.println("Positives : " + sample.getPositives());
                    System.out.println("Total : " + sample.getTotal());
                }
            }

            System.out.println("Response Code : " + report.getResponseCode());
            System.out.println("Verbose Message : " + report.getVerboseMessage());
        }
    }
    
    public void printScanReports(String[] resources,VTReportType type){
        FileScanReport[] reports = null;
        List<IPAddressReport> ipReports = null;
        if (type == VTReportType.URL){
            reports = getUrlScanReports(resources);
        } else if (type == VTReportType.FILE) {
            reports = getFileScanReports(resources);
        } else if (type == VTReportType.IP) {
            ipReports = getIPAddressReport(resources);
        }
        if (reports != null){
                for (FileScanReport report: reports){
                    printScanReport(report);
            }
        }
        if (ipReports != null){
            for (IPAddressReport ipReport : ipReports){
                printIPReport(ipReport);
            }
        }
        
    }
}
