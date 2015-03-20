package net.hackosis.semfor.parsers;

import com.kanishka.virustotal.dto.FileScanReport;
import com.kanishka.virustotal.dto.VirusScanInfo;
import com.kanishka.virustotal.exception.APIKeyNotFoundException;
import com.kanishka.virustotal.exception.QuotaExceededException;
import com.kanishka.virustotal.exception.UnauthorizedAccessException;
import com.kanishka.virustotalv2.VirusTotalConfig;
import com.kanishka.virustotalv2.VirustotalPublicV2;
import com.kanishka.virustotalv2.VirustotalPublicV2Impl;
import java.io.IOException;
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
    
    private FileScanReport getFileScanReport(String resource){
        FileScanReport report = null;
        try{
           report = virusTotalRef.getScanReport(resource);
        } catch (IOException ex){
            System.err.println("I/O Error: " + ex.getMessage());
        } catch (UnauthorizedAccessException ex){
            System.err.println("Unauthorized Access: " + ex.getMessage());
        } catch (QuotaExceededException ex){
            System.err.println("Quota Exceeded. Try again later: " + ex.getMessage());
        }
        return report;
    }
    
    public void printFileScanReport(String resource){
        FileScanReport report = getFileScanReport(resource);
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
}
