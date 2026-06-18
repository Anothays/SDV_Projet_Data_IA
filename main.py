import feedparser

def main():
    
    url = "https://www.cert.ssi.gouv.fr/avis/feed/"
    rss_feed = feedparser.parse(url)
    
    print("Hello from examen!")

    for entry in rss_feed.entries:
        print("Titre :",entry.title)
        print("Description:", entry.description)
        print("Lien :", entry.link)
        print("Date :", entry.published)


if __name__ == "__main__":
    main()
