import pandas as pd

def build_timeline(df):

    if "time" not in df.columns:
        return None

    # Convert epoch timestamp to real datetime
    df["time"] = pd.to_datetime(df["time"], unit="s")

    # Create minute buckets
    df["minute"] = df["time"].dt.floor("min")

    timeline = df.groupby("minute").size().reset_index(name="events")

    return timeline
