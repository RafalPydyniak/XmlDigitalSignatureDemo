package pl.pydyniak.signature;

/**
 * Created by pydyra on 2/20/2018.
 */
public class Token {
    private long slotId;
    private String label;

    public Token(long slotId, String label) {
        this.slotId = slotId;
        this.label = label;
    }

    public long getSlotId() {
        return slotId;
    }

    public String getLabel() {
        return label;
    }

    @Override
    public String toString() {
        return slotId + ": " + label;
    }
}
