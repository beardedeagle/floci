package io.github.hectorvent.floci.services.transfer.model;

import java.util.List;

public class TransferRecord {

    private String transferId;
    private String connectorId;
    private List<FileTransferResult> results;

    public TransferRecord() {}

    public String getTransferId() { return transferId; }
    public void setTransferId(String transferId) { this.transferId = transferId; }

    public String getConnectorId() { return connectorId; }
    public void setConnectorId(String connectorId) { this.connectorId = connectorId; }

    public List<FileTransferResult> getResults() { return results; }
    public void setResults(List<FileTransferResult> results) { this.results = results; }
}
