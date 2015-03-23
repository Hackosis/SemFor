package net.hackosis.semfor;

import net.hackosis.semfor.parsers.VTReportType;
import net.hackosis.semfor.parsers.VirusTotalParser;

/**
 *
 * @author root
 */
public class SemFor {
    public static void main(String[] args){
        SemFor app = new SemFor();
        app.parseEvidenceItems();
    }
    
    private void parseEvidenceItems(){
        VirusTotalParser vtParser = new VirusTotalParser();
        String[] filesToScan = {"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"};
        String[] urlsToScan = {"mahamegha.com","mahamegha.info"};
        String[] ipsToScan = {"208.115.233.154"};
        //vtParser.printScanReports(filesToScan, VTReportType.FILE);
        //vtParser.printScanReports(urlsToScan, VTReportType.URL);
        vtParser.printScanReports(ipsToScan, VTReportType.IP);
    }
}
