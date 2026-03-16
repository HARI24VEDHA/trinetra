import geoip2.database
import os

reader = None

if os.path.exists("data/GeoLite2-City.mmdb"):
    reader = geoip2.database.Reader("data/GeoLite2-City.mmdb")


def locate_ips(df):

    locations=[]

    if reader is None:
        return locations

    for ip in df["dst_ip"].unique():

        try:

            response = reader.city(ip)

            locations.append({
                "ip":ip,
                "latitude":response.location.latitude,
                "longitude":response.location.longitude
            })

        except:
            pass

    return locations
